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
	"slices"
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
	// ProposalRetracted marks an applied proposal whose relationship was
	// removed. Automatic attribution never writes it again.
	ProposalRetracted = "retracted"
)

// ProposalKindOrgUnit marks a proposal to record an organization as a unit
// of another with an org_unit relationship.
const ProposalKindOrgUnit = "org_unit"

// AutomaticReviewer is the reviewer recorded for proposals written during
// an enumeration without a person's review.
const AutomaticReviewer = "amass-ai (automatic)"

// OwnershipProposal is a reviewed-before-written proposal to record an
// organization as an asset's owner with one OAM relationship.
type OwnershipProposal struct {
	ID string `json:"id"`
	// Kind is empty for an ownership attribution, or ProposalKindOrgUnit for
	// a department recorded by the family lens.
	Kind      string       `json:"kind,omitempty"`
	Owner     string       `json:"owner"`
	OwnerID   string       `json:"owner_id"`
	Asset     string       `json:"asset"`
	AssetID   string       `json:"asset_id"`
	AssetType string       `json:"asset_type"`
	Edge      ProposedEdge `json:"edge"`
	Score     float64      `json:"score"`
	Decision  string       `json:"decision"`
	Signals   []string     `json:"signals"`
	// SignalIDs are the catalog signals behind Signals, each once; `amass
	// review signals` explains them.
	SignalIDs []string `json:"signal_ids,omitempty"`
	Gains     []string `json:"gains,omitempty"`
	Evidence  []string `json:"evidence"`
	// Witness holds the evidence as stored relationships.
	Witness []WitnessEdge `json:"witness,omitempty"`
	// ModelID and ModelScore record the ownership model's view, when one
	// decided the proposal; the score is its probability of ownership.
	ModelID    string    `json:"model_id,omitempty"`
	ModelScore float64   `json:"model_score,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
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
			if s.Signal != "" && !slices.Contains(p.SignalIDs, s.Signal) {
				p.SignalIDs = append(p.SignalIDs, s.Signal)
			}
			for _, w := range s.Witness {
				line := (EvidenceItem{WitnessEdge: w}).Line()
				line = strings.TrimPrefix(line, ": ")
				if !seen[line] {
					seen[line] = true
					p.Evidence = append(p.Evidence, line)
					p.Witness = append(p.Witness, w)
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
	if o.Status != ProposalRejected && o.Status != ProposalApplied && o.Status != ProposalRetracted {
		return fmt.Errorf("invalid ownership status %q", o.Status)
	}
	if o.Status == ProposalApplied && o.EdgeID == "" {
		return errors.New("an applied proposal records the edge it created")
	}

	o.At = time.Now().UTC()
	return j.append("ownership_outcome", o)
}

// OwnershipEntry is a proposal with its latest outcome and advice.
type OwnershipEntry struct {
	Proposal OwnershipProposal `json:"proposal"`
	Status   string            `json:"status"`
	Outcome  *OwnershipOutcome `json:"outcome,omitempty"`
	Advice   *OwnershipAdvice  `json:"advice,omitempty"`
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
		case "ownership_advice":
			var a OwnershipAdvice
			if err := json.Unmarshal(rec.Data, &a); err != nil {
				return nil, err
			}
			if e, ok := state[a.ProposalID]; ok {
				e.Advice = &a
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
		if p.Kind == ProposalKindOrgUnit {
			fmt.Fprintf(&b, "%s [%s, %s] %s is a unit of %s\n  would record: %s\n", p.ID, e.Status, p.Decision,
				p.Asset, p.Owner, p.Edge)
		} else {
			fmt.Fprintf(&b, "%s [%s, %s %.2f] %s owns %s %s\n  would record: %s\n", p.ID, e.Status, p.Decision,
				p.Score, p.Owner, p.AssetType, p.Asset, p.Edge)
		}
		if len(p.Gains) > 0 {
			fmt.Fprintf(&b, "  brings: %s\n", strings.Join(p.Gains, ", "))
		}

		fmt.Fprintf(&b, "  signals: %s\n", strings.Join(p.Signals, "; "))
		for _, id := range p.SignalIDs {
			if def, ok := ownershipSignal(id); ok {
				fmt.Fprintf(&b, "  why: %s (%s): %s\n", def.Title, def.Strength, def.Rationale)
			}
		}
		if p.ModelID != "" {
			fmt.Fprintf(&b, "  model %s: %.2f\n", p.ModelID, p.ModelScore)
		}
		for _, ev := range p.Evidence {
			fmt.Fprintf(&b, "    %s\n", ev)
		}
		if a := e.Advice; a != nil {
			if a.Verified {
				fmt.Fprintf(&b, "  advice from %s: %s. %s\n", a.Model, a.Recommendation, a.Rationale)
			} else {
				fmt.Fprintf(&b, "  advice from %s was rejected: %s\n", a.Model, strings.Join(a.Problems, "; "))
			}
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

// AssetLabel is the name an answer uses for a.
func AssetLabel(a Asset) string {
	return assetLabel(a)
}
