// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// Reconsideration: a correlator's conclusion is not a one-shot verdict. Every
// applied relation records the witness edges it rested on, and a re-check
// re-tests that witness as the Asset Database changes. When a witnessed
// relationship is gone the conclusion no longer holds and is reopened: a write
// that AI applied on its own is retracted (recorded with RecheckReviewer, so
// RelationRedecidable lets it return once the evidence does), while a write a
// person approved is flagged for re-review rather than silently undone — a
// human decision stays sticky (ai-design-principles.md, principle 9). The
// strengthening direction — re-scoring and re-surfacing a pending proposal as
// its signals change — is handled when a correlator re-submits the same stable
// proposal ID.

// RelationRecheckResult lists what a re-check changed.
type RelationRecheckResult struct {
	Checked   int                `json:"checked"`
	Retracted []RelationProposal `json:"retracted,omitempty"`
	Flagged   []RelationProposal `json:"flagged,omitempty"`
}

// relationRecheckFlag records that an applied, human-approved relation's
// witness is gone, so it can be surfaced for re-review without changing the
// relationship (the person decides whether to keep it).
type relationRecheckFlag struct {
	ProposalID string    `json:"proposal_id"`
	Missing    string    `json:"missing"`
	At         time.Time `json:"at"`
}

// witnessChecker returns the first witnessed relationship that no longer
// exists, or "" when all still do. It is injectable so the orchestration can be
// tested without a graph; RecheckRelations supplies the real missingWitness.
type witnessChecker func(witness []graph.WitnessEdge) (string, error)

// RecheckRelations re-tests every applied relation proposal (of the given
// correlator kind, or all kinds when kind is empty) against the witness it
// recorded. See the package note above for what reopening means.
func RecheckRelations(ctx context.Context, g graph.Graph, w RelationDeleter, j *Journal,
	kind string) (RelationRecheckResult, error) {
	return recheckRelations(ctx, w, j, kind, func(wit []graph.WitnessEdge) (string, error) {
		return missingWitness(ctx, g, wit)
	})
}

func recheckRelations(ctx context.Context, w RelationDeleter, j *Journal, kind string,
	check witnessChecker) (RelationRecheckResult, error) {
	var res RelationRecheckResult

	proposals, status, err := j.relationRecords(kind)
	if err != nil {
		return res, err
	}

	ids := make([]string, 0, len(proposals))
	for id := range proposals {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		if status[id] != ProposalApplied {
			continue
		}
		p := proposals[id]
		if len(p.Witness) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}

		reviewer, edgeID := j.relationApplyOutcome(id)
		res.Checked++

		missing, err := check(p.Witness)
		if err != nil {
			return res, err
		}
		if missing == "" {
			continue
		}

		if isAIReviewer(reviewer) {
			if edgeID != "" {
				if err := w.DeleteEdge(ctx, edgeID); err != nil {
					return res, fmt.Errorf("retract %s: %w", id, err)
				}
			}
			if err := j.RecordRelation(RelationOutcome{ProposalID: id, Status: ProposalRetracted,
				Reviewer: RecheckReviewer, EdgeID: edgeID}); err != nil {
				return res, err
			}
			res.Retracted = append(res.Retracted, p)
		} else {
			if err := j.flagRelationRecheck(id, missing); err != nil {
				return res, err
			}
			res.Flagged = append(res.Flagged, p)
		}
	}

	return res, nil
}

// isAIReviewer reports whether a reviewer is one of amass's automatic ones
// (automatic attribution or a re-check), as opposed to a person.
func isAIReviewer(reviewer string) bool {
	return strings.HasPrefix(reviewer, "amass-ai")
}

// RelationRedecidable reports whether a relation proposal can be acted on again
// automatically: it is still pending, or it was retracted by a re-check (not by
// a person). A person's rejection or retraction is sticky.
func RelationRedecidable(status, reviewer string) bool {
	return status == ProposalPending ||
		(status == ProposalRetracted && reviewer == RecheckReviewer)
}

// relationApplyOutcome returns the reviewer and edge id of the latest apply of
// a relation proposal, so a re-check can tell an AI write from a human one.
func (j *Journal) relationApplyOutcome(id string) (string, string) {
	hist, err := j.History()
	if err != nil {
		return "", ""
	}

	var reviewer, edgeID string
	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil || head.Kind != "relation_outcome" {
			continue
		}
		var o RelationOutcome
		if json.Unmarshal(head.Data, &o) == nil && o.ProposalID == id && o.Status == ProposalApplied {
			reviewer, edgeID = o.Reviewer, o.EdgeID
		}
	}

	return reviewer, edgeID
}

// flagRelationRecheck records that an applied, human-approved relation's
// witness is gone, for later surfacing; it changes no relationship.
func (j *Journal) flagRelationRecheck(id, missing string) error {
	if id == "" {
		return errors.New("proposal ID required")
	}

	return j.append("relation_recheck", relationRecheckFlag{ProposalID: id, Missing: missing, At: time.Now().UTC()})
}

// RelationFlags returns, for a correlator kind (or all kinds when empty), the
// applied proposals a re-check flagged for re-review and the evidence each is
// missing, so the CLI and MCP can surface them.
func (j *Journal) RelationFlags(kind string) (map[string]string, error) {
	flags := map[string]string{}
	hist, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return flags, nil
	}
	if err != nil {
		return nil, err
	}

	proposals, _, err := j.relationRecords(kind)
	if err != nil {
		return nil, err
	}

	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil || head.Kind != "relation_recheck" {
			continue
		}
		var f relationRecheckFlag
		if json.Unmarshal(head.Data, &f) == nil && f.ProposalID != "" {
			if _, ok := proposals[f.ProposalID]; ok || kind == "" {
				flags[f.ProposalID] = f.Missing
			}
		}
	}

	return flags, nil
}
