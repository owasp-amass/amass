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

	"github.com/owasp-amass/amass/v5/internal/lens"
)

// IdentityRecord is everything a correction changed, so it can be undone.
type IdentityRecord struct {
	OrgID string `json:"org_id"`
	// Before is the organization's content before the correction.
	Before json.RawMessage `json:"before"`
	// Edges are the relationships the correction touched: deleted when
	// only enrichment sources recorded them, otherwise only those sources'
	// tags were removed.
	Edges []CorrectedEdge `json:"edges"`
}

// CorrectedEdge is one relationship a correction removed or untagged.
type CorrectedEdge struct {
	MergedEdge
	Deleted     bool        `json:"deleted"`
	RemovedTags []MergedTag `json:"removed_tags,omitempty"`
}

// IdentityCorrector applies and undoes identity corrections.
type IdentityCorrector interface {
	CorrectIdentity(ctx context.Context, c lens.IdentityConflict) (IdentityRecord, error)
	UndoIdentityCorrection(ctx context.Context, rec IdentityRecord) error
}

// IdentityOutcome records a decision on an identity correction.
type IdentityOutcome struct {
	ProposalID string          `json:"proposal_id"`
	Status     string          `json:"status"`
	Reviewer   string          `json:"reviewer"`
	Record     *IdentityRecord `json:"record,omitempty"`
	At         time.Time       `json:"at"`
}

// IdentityEntry is an identity correction proposal with its latest outcome.
type IdentityEntry struct {
	Proposal lens.IdentityConflict `json:"proposal"`
	Status   string                `json:"status"`
	Outcome  *IdentityOutcome      `json:"outcome,omitempty"`
}

// SubmitIdentityConflicts records conflicts not already in the journal.
func (j *Journal) SubmitIdentityConflicts(conflicts []lens.IdentityConflict) ([]lens.IdentityConflict, error) {
	state, err := j.IdentityState()
	if err != nil {
		return nil, err
	}

	var added []lens.IdentityConflict
	for _, c := range conflicts {
		if c.ID == "" || c.OrgID == "" {
			return added, errors.New("identity correction needs an ID and an organization")
		}
		if _, ok := state[c.ID]; ok {
			continue
		}
		if err := j.append("identity_proposal", c); err != nil {
			return added, err
		}

		added = append(added, c)
	}

	return added, nil
}

// RecordIdentity records a decision on an identity correction.
func (j *Journal) RecordIdentity(o IdentityOutcome) error {
	if o.ProposalID == "" || o.Reviewer == "" {
		return errors.New("proposal ID and reviewer required")
	}
	switch o.Status {
	case ProposalRejected, ProposalRetracted:
	case ProposalApplied:
		if o.Record == nil {
			return errors.New("an applied correction records what it changed")
		}
	default:
		return fmt.Errorf("invalid identity status %q", o.Status)
	}

	o.At = time.Now().UTC()
	return j.append("identity_outcome", o)
}

// IdentityState replays the journal into each identity correction's
// current status. A missing journal is empty.
func (j *Journal) IdentityState() (map[string]*IdentityEntry, error) {
	state := map[string]*IdentityEntry{}
	lines, err := j.History()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}

		return nil, err
	}
	for _, line := range lines {
		var rec struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, err
		}
		switch rec.Kind {
		case "identity_proposal":
			var c lens.IdentityConflict
			if err := json.Unmarshal(rec.Data, &c); err != nil {
				return nil, err
			}
			if _, ok := state[c.ID]; !ok {
				state[c.ID] = &IdentityEntry{Proposal: c, Status: ProposalPending}
			}
		case "identity_outcome":
			var o IdentityOutcome
			if err := json.Unmarshal(rec.Data, &o); err != nil {
				return nil, err
			}
			if e, ok := state[o.ProposalID]; ok {
				e.Status, e.Outcome = o.Status, &o
			}
		}
	}

	// pending corrections reach the organization and relationships merges
	// moved them to
	r := readRedirects(lines)
	for _, e := range state {
		if e.Status != ProposalPending {
			continue
		}
		r.redirected(&e.Proposal.OrgID)
		for i, id := range e.Proposal.EdgeIDs {
			e.Proposal.EdgeIDs[i] = r.Edge(id)
		}
	}

	return state, nil
}

// IdentityEntries lists the journal's identity corrections, pending first.
func (j *Journal) IdentityEntries() ([]IdentityEntry, error) {
	state, err := j.IdentityState()
	if err != nil {
		return nil, err
	}

	out := make([]IdentityEntry, 0, len(state))
	for _, e := range state {
		out = append(out, *e)
	}
	sort.Slice(out, func(a, b int) bool {
		pa, pb := out[a].Status == ProposalPending, out[b].Status == ProposalPending
		if pa != pb {
			return pa
		}
		return out[a].Proposal.Organization < out[b].Proposal.Organization
	})
	return out, nil
}

// FormatIdentityEntries renders identity corrections for review.
func FormatIdentityEntries(entries []IdentityEntry) string {
	if len(entries) == 0 {
		return "No identity corrections in the journal.\n"
	}

	var b strings.Builder
	for i, e := range entries {
		if i > 0 {
			b.WriteString("\n")
		}

		p := e.Proposal
		fmt.Fprintf(&b, "%s  %s\n", p.ID, strings.ToUpper(e.Status))
		fmt.Fprintf(&b, "  %s [%s]: remove legal identity %q (%s), %d relationship(s) only %s recorded\n",
			p.Organization, p.OrgID, p.LegalName, p.Jurisdiction, len(p.EdgeIDs),
			strings.Join(lens.LoadIdentityChecks().EnrichmentSources, ", "))
		for _, r := range p.Reasons {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
		if o := e.Outcome; o != nil {
			fmt.Fprintf(&b, "  %s by %s at %s\n", o.Status, o.Reviewer, o.At.Format(time.RFC3339))
		}
	}

	return b.String()
}

// ApplyIdentityCorrection corrects a pending proposal's organization and
// records what changed.
func ApplyIdentityCorrection(ctx context.Context, c IdentityCorrector, j *Journal, p lens.IdentityConflict,
	reviewer string) (IdentityRecord, error) {
	rec, err := c.CorrectIdentity(ctx, p)
	if err != nil {
		return rec, fmt.Errorf("correct %s [%s]: %w", p.Organization, p.OrgID, err)
	}
	if err := j.RecordIdentity(IdentityOutcome{ProposalID: p.ID, Status: ProposalApplied, Reviewer: reviewer,
		Record: &rec}); err != nil {
		return rec, fmt.Errorf("%s was corrected but the journal was not updated: %w", p.Organization, err)
	}

	return rec, nil
}
