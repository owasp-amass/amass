// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
)

// MergedTag is a stored property, kept so a merge can be undone.
type MergedTag struct {
	Type     string          `json:"type"`
	Property json.RawMessage `json:"property"`
}

// MergedEdge is one of the duplicate's relationships and what the merge
// did with it.
type MergedEdge struct {
	// ID is the duplicate's original edge.
	ID string `json:"id"`
	// Outgoing reports whether the duplicate was the edge's source.
	Outgoing     bool            `json:"outgoing"`
	OtherID      string          `json:"other_id"`
	Label        string          `json:"label"`
	RelationType string          `json:"relation_type"`
	Relation     json.RawMessage `json:"relation"`
	Tags         []MergedTag     `json:"tags,omitempty"`
	// SurvivorEdgeID is the survivor's edge that now carries the
	// relationship. Created reports whether the merge created it; when it
	// already existed, AddedTagIDs are the tags the merge added to it.
	SurvivorEdgeID string   `json:"survivor_edge_id,omitempty"`
	Created        bool     `json:"created,omitempty"`
	AddedTagIDs    []string `json:"added_tag_ids,omitempty"`
	// Skipped says why the relationship was not moved, such as an edge
	// between the two merged organizations.
	Skipped string `json:"skipped,omitempty"`
}

// MergeRecord is everything a merge changed, so it can be undone.
type MergeRecord struct {
	SurvivorID  string `json:"survivor_id"`
	DuplicateID string `json:"duplicate_id"`
	// DuplicateAsset is the deleted organization's content.
	DuplicateAsset json.RawMessage `json:"duplicate_asset"`
	DuplicateTags  []MergedTag     `json:"duplicate_tags,omitempty"`
	// SurvivorTagIDs are the properties the merge added to the survivor.
	SurvivorTagIDs []string     `json:"survivor_tag_ids,omitempty"`
	Edges          []MergedEdge `json:"edges"`
	// FilledFields are the survivor's empty organization fields the merge
	// filled from the duplicate. Undoing the merge leaves them: the Asset
	// Database cannot clear a field.
	FilledFields []string `json:"filled_fields,omitempty"`
	// FillError says why the fields could not be filled after the merge.
	FillError string `json:"fill_error,omitempty"`
}

// OrganizationMerger merges two organizations in the Asset Database and
// undoes a merge from its record.
type OrganizationMerger interface {
	MergeOrganizations(ctx context.Context, survivorID, duplicateID string, confidence int) (MergeRecord, error)
	UnmergeOrganizations(ctx context.Context, rec MergeRecord) (string, error)
}

// DuplicateProposal is a reviewed-before-written proposal to merge one
// organization into another.
type DuplicateProposal struct {
	ID          string   `json:"id"`
	Survivor    string   `json:"survivor"`
	SurvivorID  string   `json:"survivor_id"`
	Duplicate   string   `json:"duplicate"`
	DuplicateID string   `json:"duplicate_id"`
	Score       float64  `json:"score"`
	Decision    string   `json:"decision"`
	Signals     []string `json:"signals"`
	// SignalIDs are the catalog signals behind Signals, each once; `amass ai
	// duplicate-signals` explains them.
	SignalIDs []string  `json:"signal_ids,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// DuplicateOutcome records a decision on a merge proposal. An applied
// merge carries its record; a retracted one the restored organization.
type DuplicateOutcome struct {
	ProposalID string       `json:"proposal_id"`
	Status     string       `json:"status"`
	Reviewer   string       `json:"reviewer"`
	Merge      *MergeRecord `json:"merge,omitempty"`
	RestoredID string       `json:"restored_id,omitempty"`
	At         time.Time    `json:"at"`
}

// DuplicateEntry is a merge proposal with its latest outcome.
type DuplicateEntry struct {
	Proposal DuplicateProposal `json:"proposal"`
	Status   string            `json:"status"`
	Outcome  *DuplicateOutcome `json:"outcome,omitempty"`
}

// DuplicatePrefix starts every merge proposal ID.
const DuplicatePrefix = "dup-"

// DuplicateProposalID is a stable identifier for merging one organization
// into another; it does not depend on which one survives.
func DuplicateProposalID(a, b string) string {
	ids := []string{a, b}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(ids[0] + "\x00" + ids[1]))
	return DuplicatePrefix + hex.EncodeToString(sum[:8])
}

// DuplicateProposals turns a duplicate report's propose and review
// candidates into proposals. Weak candidates are only reported.
func DuplicateProposals(r DuplicateReport) []DuplicateProposal {
	var out []DuplicateProposal
	now := time.Now().UTC()
	for _, c := range r.Candidates {
		if c.Decision == GapWeak {
			continue
		}

		p := DuplicateProposal{ID: DuplicateProposalID(c.Survivor.ID, c.Duplicate.ID),
			Survivor: AssetLabel(c.Survivor), SurvivorID: c.Survivor.ID, Duplicate: AssetLabel(c.Duplicate),
			DuplicateID: c.Duplicate.ID, Score: c.Score, Decision: c.Decision, CreatedAt: now}
		for _, s := range c.Signals {
			def, _ := duplicateSignal(s.Signal)
			p.Signals = append(p.Signals, def.Title+": "+s.Via)
			if !slices.Contains(p.SignalIDs, s.Signal) {
				p.SignalIDs = append(p.SignalIDs, s.Signal)
			}
		}

		out = append(out, p)
	}

	return out
}

// SubmitDuplicates records proposals not already in the journal and
// returns the ones it added.
func (j *Journal) SubmitDuplicates(proposals []DuplicateProposal) ([]DuplicateProposal, error) {
	state, err := j.DuplicateState()
	if err != nil {
		return nil, err
	}

	var added []DuplicateProposal
	for _, p := range proposals {
		if p.ID == "" || p.SurvivorID == "" || p.DuplicateID == "" {
			return added, errors.New("merge proposal needs an ID and two organizations")
		}
		if _, ok := state[p.ID]; ok {
			continue
		}
		if err := j.append("duplicate_proposal", p); err != nil {
			return added, err
		}

		added = append(added, p)
	}

	return added, nil
}

// RecordDuplicate records a decision on a merge proposal.
func (j *Journal) RecordDuplicate(o DuplicateOutcome) error {
	if o.ProposalID == "" || o.Reviewer == "" {
		return errors.New("proposal ID and reviewer required")
	}
	switch o.Status {
	case ProposalRejected:
	case ProposalApplied:
		if o.Merge == nil {
			return errors.New("an applied merge records what it changed")
		}
	case ProposalRetracted:
		if o.RestoredID == "" {
			return errors.New("a retracted merge records the restored organization")
		}
	default:
		return fmt.Errorf("invalid merge status %q", o.Status)
	}

	o.At = time.Now().UTC()
	return j.append("duplicate_outcome", o)
}

// DuplicateState replays the journal into each merge proposal's current
// status. A missing journal is empty.
func (j *Journal) DuplicateState() (map[string]*DuplicateEntry, error) {
	state := map[string]*DuplicateEntry{}
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
		case "duplicate_proposal":
			var p DuplicateProposal
			if err := json.Unmarshal(rec.Data, &p); err != nil {
				return nil, err
			}
			if _, ok := state[p.ID]; !ok {
				state[p.ID] = &DuplicateEntry{Proposal: p, Status: ProposalPending}
			}
		case "duplicate_outcome":
			var o DuplicateOutcome
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

// DuplicateEntries lists the journal's merge proposals, pending first,
// then by score.
func (j *Journal) DuplicateEntries() ([]DuplicateEntry, error) {
	state, err := j.DuplicateState()
	if err != nil {
		return nil, err
	}

	out := make([]DuplicateEntry, 0, len(state))
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

// FormatDuplicateEntries renders merge proposals for review.
func FormatDuplicateEntries(entries []DuplicateEntry) string {
	if len(entries) == 0 {
		return "No merge proposals in the journal.\n"
	}

	var b strings.Builder
	for i, e := range entries {
		if i > 0 {
			b.WriteString("\n")
		}

		p := e.Proposal
		fmt.Fprintf(&b, "%s  %s (%s, score %.2f)\n", p.ID, strings.ToUpper(e.Status), p.Decision, p.Score)
		fmt.Fprintf(&b, "  merge %s [%s] into %s [%s]\n", p.Duplicate, p.DuplicateID, p.Survivor, p.SurvivorID)
		for _, s := range p.Signals {
			fmt.Fprintf(&b, "  - %s\n", s)
		}
		if o := e.Outcome; o != nil {
			switch o.Status {
			case ProposalApplied:
				moved := 0
				if o.Merge != nil {
					for _, m := range o.Merge.Edges {
						if m.Skipped == "" {
							moved++
						}
					}
				}
				fmt.Fprintf(&b, "  merged by %s at %s: %d relationships moved\n", o.Reviewer,
					o.At.Format(time.RFC3339), moved)
				if o.Merge != nil && len(o.Merge.FilledFields) > 0 {
					fmt.Fprintf(&b, "  filled %s from the duplicate\n", strings.Join(o.Merge.FilledFields, ", "))
				}
			case ProposalRetracted:
				fmt.Fprintf(&b, "  undone by %s at %s: restored as [%s]\n", o.Reviewer, o.At.Format(time.RFC3339),
					o.RestoredID)
				if o.Merge != nil && len(o.Merge.FilledFields) > 0 {
					fmt.Fprintf(&b, "  %s [%s] keeps %s filled by the merge\n", p.Survivor, p.SurvivorID,
						strings.Join(o.Merge.FilledFields, ", "))
				}
			default:
				fmt.Fprintf(&b, "  %s by %s at %s\n", o.Status, o.Reviewer, o.At.Format(time.RFC3339))
			}
		}
	}

	return b.String()
}

// MergeConfidence is the source confidence written on relationships a
// merge moves: the proposal's score as a percentage.
func MergeConfidence(p DuplicateProposal) int {
	return int(math.Round(math.Max(0, math.Min(1, p.Score)) * 100))
}

// ApplyMerge merges a pending proposal's duplicate into its survivor and
// records the merge, so it can be undone.
func ApplyMerge(ctx context.Context, m OrganizationMerger, j *Journal, p DuplicateProposal,
	reviewer string) (MergeRecord, error) {
	rec, err := m.MergeOrganizations(ctx, p.SurvivorID, p.DuplicateID, MergeConfidence(p))
	if err != nil {
		return rec, fmt.Errorf("merge %s [%s] into %s [%s]: %w", p.Duplicate, p.DuplicateID, p.Survivor,
			p.SurvivorID, err)
	}
	if err := j.RecordDuplicate(DuplicateOutcome{ProposalID: p.ID, Status: ProposalApplied, Reviewer: reviewer,
		Merge: &rec}); err != nil {
		return rec, fmt.Errorf("%s was merged but the journal was not updated: %w", p.Duplicate, err)
	}

	return rec, nil
}
