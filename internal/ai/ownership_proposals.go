// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// InferenceSource is the source name on relationships written from
// approved AI proposals, so they can always be told apart from collected
// data.
const InferenceSource = "amass-ai"

// Ownership proposal statuses in the journal.
const (
	ProposalPending  = "proposed"
	ProposalRejected = "rejected"
	ProposalApplied  = "applied"
)

// OwnershipProposal is a reviewed-before-written proposal to record an
// organization as an asset's owner with one OAM relationship.
type OwnershipProposal struct {
	ID        string       `json:"id"`
	Owner     string       `json:"owner"`
	OwnerID   string       `json:"owner_id"`
	Asset     string       `json:"asset"`
	AssetID   string       `json:"asset_id"`
	AssetType string       `json:"asset_type"`
	Edge      ProposedEdge `json:"edge"`
	Score     float64      `json:"score"`
	Decision  string       `json:"decision"`
	Signals   []string     `json:"signals"`
	Gains     []string     `json:"gains,omitempty"`
	Evidence  []string     `json:"evidence"`
	CreatedAt time.Time    `json:"created_at"`
}

// OwnershipOutcome records a reviewer's decision, and for an applied
// proposal the stored edge it created.
type OwnershipOutcome struct {
	ProposalID string    `json:"proposal_id"`
	Status     string    `json:"status"`
	Reviewer   string    `json:"reviewer"`
	EdgeID     string    `json:"edge_id,omitempty"`
	At         time.Time `json:"at"`
}

// ProposalID is a stable identifier for proposing edge e.
func ProposalID(e ProposedEdge) string {
	sum := sha256.Sum256([]byte(e.FromID + "\x00" + e.Label + "\x00" + e.RelationType + "\x00" + e.ToID))
	return "own-" + hex.EncodeToString(sum[:8])
}

// OwnershipProposals turns a gap report's candidates into proposals: those
// decided propose or review that have exactly one attachment. Weak and
// ambiguous candidates are left to the answer.
func OwnershipProposals(r OwnershipGapReport) []OwnershipProposal {
	var out []OwnershipProposal
	now := time.Now().UTC()
	for _, c := range r.Candidates {
		if c.Attachment == nil || len(c.Alternatives) > 0 || c.Decision == GapWeak {
			continue
		}

		p := OwnershipProposal{ID: ProposalID(*c.Attachment), Owner: assetLabel(r.Owner), OwnerID: r.Owner.ID,
			Asset: c.Asset, AssetID: c.AssetID, AssetType: c.Type, Edge: *c.Attachment, Score: c.Score,
			Decision: c.Decision, Gains: c.Gains, CreatedAt: now}
		seen := map[string]bool{}
		for _, s := range c.Signals {
			p.Signals = append(p.Signals, s.Kind+" via "+s.Via)
			for _, w := range s.Witness {
				line := (EvidenceItem{WitnessEdge: w}).Line()
				line = strings.TrimPrefix(line, ": ")
				if !seen[line] {
					seen[line] = true
					p.Evidence = append(p.Evidence, line)
				}
			}
		}

		out = append(out, p)
	}

	return out
}

// SubmitOwnership records proposals not already in the journal and returns
// the ones it added.
func (j *Journal) SubmitOwnership(proposals []OwnershipProposal) ([]OwnershipProposal, error) {
	state, err := j.OwnershipState()
	if err != nil {
		return nil, err
	}

	var added []OwnershipProposal
	for _, p := range proposals {
		if p.ID == "" || p.Edge.FromID == "" || p.Edge.ToID == "" {
			return added, errors.New("ownership proposal needs an ID and an edge")
		}
		if _, ok := state[p.ID]; ok {
			continue
		}
		if err := j.append("ownership_proposal", p); err != nil {
			return added, err
		}

		added = append(added, p)
	}

	return added, nil
}

// RecordOwnership records a reviewer's decision on a proposal.
func (j *Journal) RecordOwnership(o OwnershipOutcome) error {
	if o.ProposalID == "" || o.Reviewer == "" {
		return errors.New("proposal ID and reviewer required")
	}
	if o.Status != ProposalRejected && o.Status != ProposalApplied {
		return fmt.Errorf("invalid ownership status %q", o.Status)
	}
	if o.Status == ProposalApplied && o.EdgeID == "" {
		return errors.New("an applied proposal records the edge it created")
	}

	o.At = time.Now().UTC()
	return j.append("ownership_outcome", o)
}

// OwnershipEntry is a proposal with its latest outcome.
type OwnershipEntry struct {
	Proposal OwnershipProposal `json:"proposal"`
	Status   string            `json:"status"`
	Outcome  *OwnershipOutcome `json:"outcome,omitempty"`
}

// OwnershipState replays the journal into each proposal's current status.
// A missing journal is empty.
func (j *Journal) OwnershipState() (map[string]*OwnershipEntry, error) {
	state := map[string]*OwnershipEntry{}
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
		case "ownership_proposal":
			var p OwnershipProposal
			if err := json.Unmarshal(rec.Data, &p); err != nil {
				return nil, err
			}
			if _, ok := state[p.ID]; !ok {
				state[p.ID] = &OwnershipEntry{Proposal: p, Status: ProposalPending}
			}
		case "ownership_outcome":
			var o OwnershipOutcome
			if err := json.Unmarshal(rec.Data, &o); err != nil {
				return nil, err
			}
			if e, ok := state[o.ProposalID]; ok {
				e.Status, e.Outcome = o.Status, &o
			}
		}
	}

	return state, nil
}

// OwnershipEntries lists the journal's ownership proposals, pending first,
// then by score.
func (j *Journal) OwnershipEntries() ([]OwnershipEntry, error) {
	state, err := j.OwnershipState()
	if err != nil {
		return nil, err
	}

	out := make([]OwnershipEntry, 0, len(state))
	for _, e := range state {
		out = append(out, *e)
	}

	sort.Slice(out, func(a, b int) bool {
		pa, pb := out[a].Status == ProposalPending, out[b].Status == ProposalPending
		if pa != pb {
			return pa
		}
		if out[a].Proposal.Score != out[b].Proposal.Score {
			return out[a].Proposal.Score > out[b].Proposal.Score
		}

		return out[a].Proposal.ID < out[b].Proposal.ID
	})
	return out, nil
}

// FormatOwnershipEntries renders entries for review.
func FormatOwnershipEntries(entries []OwnershipEntry) string {
	if len(entries) == 0 {
		return "No ownership proposals in the journal."
	}

	var b strings.Builder
	for _, e := range entries {
		p := e.Proposal
		fmt.Fprintf(&b, "%s [%s, %s %.2f] %s owns %s %s\n  would record: %s\n", p.ID, e.Status, p.Decision, p.Score,
			p.Owner, p.AssetType, p.Asset, p.Edge)
		if len(p.Gains) > 0 {
			fmt.Fprintf(&b, "  brings: %s\n", strings.Join(p.Gains, ", "))
		}

		fmt.Fprintf(&b, "  signals: %s\n", strings.Join(p.Signals, "; "))
		for _, ev := range p.Evidence {
			fmt.Fprintf(&b, "    %s\n", ev)
		}
		if e.Outcome != nil {
			fmt.Fprintf(&b, "  %s by %s at %s", e.Outcome.Status, e.Outcome.Reviewer,
				e.Outcome.At.Format(time.RFC3339))
			if e.Outcome.EdgeID != "" {
				fmt.Fprintf(&b, " (edge %s)", e.Outcome.EdgeID)
			}

			b.WriteString("\n")
		}
	}

	return strings.TrimRight(b.String(), "\n")
}
