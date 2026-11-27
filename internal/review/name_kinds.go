// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
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

// NameKindPrefix starts every name proposal ID.
const NameKindPrefix = "nk-"

// The kinds a name proposal is decided as.
const (
	NameKindPerson       = "person"
	NameKindOrganization = "organization"
)

// NameKindProposal asks what a name found in a person's field names, when
// the evidence did not settle it: a person or an organization. The raw name
// is kept on its record (graph.UncertainNameProp) until it is decided.
type NameKindProposal struct {
	ID string `json:"id"`
	// RecordID and RecordType are the record that gave the name (a
	// ContactRecord, a File), and Label the relation from it to the person
	// the field names ("person", "author", "contains").
	RecordID   string    `json:"record_id"`
	RecordType string    `json:"record_type"`
	Label      string    `json:"label"`
	Name       string    `json:"name"`
	Reasons    []string  `json:"reasons,omitempty"`
	Source     string    `json:"source,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// NameKindProposalID is a stable identifier for deciding the name given by
// a record's field.
func NameKindProposalID(recordID, label, name string) string {
	sum := sha256.Sum256([]byte(recordID + "|" + label + "|" + strings.ToLower(strings.TrimSpace(name))))
	return NameKindPrefix + hex.EncodeToString(sum[:])[:16]
}

// IsNameKindProposal reports whether id is a name proposal's.
func IsNameKindProposal(id string) bool { return strings.HasPrefix(id, NameKindPrefix) }

// NameKindOutcome records a decision on a name proposal: for an applied one
// the kind it was decided as and what was written, so it can be undone.
type NameKindOutcome struct {
	ProposalID string `json:"proposal_id"`
	Status     string `json:"status"`
	Reviewer   string `json:"reviewer"`
	Kind       string `json:"kind,omitempty"`
	// EntityID is the Person or Organization the name became, linked from
	// the record by EdgeID; Created reports whether the decision created it.
	EntityID   string    `json:"entity_id,omitempty"`
	EdgeID     string    `json:"edge_id,omitempty"`
	Created    bool      `json:"created,omitempty"`
	Confidence int       `json:"confidence,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	At         time.Time `json:"at"`
}

// NameKindAdvice is a model's answer to a name proposal it did not decide:
// a kind below the confidence to apply it, or any answer while decisions
// wait for a person (attribution journal). It is advice for the reviewer,
// never applied and never a training label.
type NameKindAdvice struct {
	ProposalID string `json:"proposal_id"`
	Model      string `json:"model"`
	Kind       string `json:"kind"`
	Confidence int    `json:"confidence"`
	Reason     string `json:"reason,omitempty"`
	// Cites are the evidence the answer rests on, as the model was given it.
	Cites []string  `json:"cites,omitempty"`
	At    time.Time `json:"at"`
}

// NameKindEntry is a name proposal with its latest outcome and advice.
type NameKindEntry struct {
	Proposal NameKindProposal `json:"proposal"`
	Status   string           `json:"status"`
	Outcome  *NameKindOutcome `json:"outcome,omitempty"`
	Advice   *NameKindAdvice  `json:"advice,omitempty"`
}

// NameKindApplier writes a decided name: the Person or Organization linked
// from its record, the kept raw name removed; and undoes it.
type NameKindApplier interface {
	ApplyNameKind(ctx context.Context, p NameKindProposal, kind string, confidence int) (NameKindOutcome, error)
	RetractNameKind(ctx context.Context, p NameKindProposal, o NameKindOutcome) error
}

// SubmitNameKinds records the proposals not already in the journal.
func (j *Journal) SubmitNameKinds(proposals []NameKindProposal) ([]NameKindProposal, error) {
	return j.submitNameKinds(proposals, false)
}

// NameKindsToAsk records the proposals not already in the journal and
// returns those for a decider to answer: the ones recorded now, and those
// already recorded that are still pending with no answer (an earlier ask
// failed, or there was no decider), as they now stand. A proposal with
// advice keeps it and is not returned.
func (j *Journal) NameKindsToAsk(proposals []NameKindProposal) ([]NameKindProposal, error) {
	return j.submitNameKinds(proposals, true)
}

func (j *Journal) submitNameKinds(proposals []NameKindProposal, unanswered bool) ([]NameKindProposal, error) {
	state, err := j.NameKindState()
	if err != nil {
		return nil, err
	}

	var added []NameKindProposal
	for _, p := range proposals {
		if p.ID == "" || p.RecordID == "" || p.Label == "" || strings.TrimSpace(p.Name) == "" {
			return added, errors.New("a name proposal needs an ID, a record, a label and a name")
		}
		if e, ok := state[p.ID]; ok {
			if unanswered && e.Status == ProposalPending && e.Advice == nil {
				added = append(added, e.Proposal)
			}
			continue
		}
		if p.CreatedAt.IsZero() {
			p.CreatedAt = time.Now().UTC()
		}
		if err := j.append("name_kind_proposal", p); err != nil {
			return added, err
		}
		state[p.ID] = &NameKindEntry{Proposal: p, Status: ProposalPending}
		added = append(added, p)
	}
	return added, nil
}

// RecordNameKind records a decision on a name proposal.
func (j *Journal) RecordNameKind(o NameKindOutcome) error {
	if o.ProposalID == "" || o.Reviewer == "" {
		return errors.New("proposal ID and reviewer required")
	}
	switch o.Status {
	case ProposalRejected, ProposalRetracted:
	case ProposalApplied:
		if (o.Kind != NameKindPerson && o.Kind != NameKindOrganization) || o.EntityID == "" {
			return errors.New("an applied name records its kind and what it became")
		}
	default:
		return fmt.Errorf("invalid name proposal status %q", o.Status)
	}

	o.At = time.Now().UTC()
	return j.append("name_kind_outcome", o)
}

// RecordNameKindAdvice records a model's advice on a name proposal.
func (j *Journal) RecordNameKindAdvice(a NameKindAdvice) error {
	if a.ProposalID == "" || a.Model == "" || a.Kind == "" {
		return errors.New("proposal ID, model and kind required")
	}
	a.At = time.Now().UTC()
	return j.append("name_kind_advice", a)
}

// NameKindState replays the journal into each name proposal's current
// status. A pending proposal's record is resolved through the merges and
// removals since (Redirects). A missing journal is empty.
func (j *Journal) NameKindState() (map[string]*NameKindEntry, error) {
	state := map[string]*NameKindEntry{}
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
		case "name_kind_proposal":
			var p NameKindProposal
			if err := json.Unmarshal(rec.Data, &p); err != nil {
				return nil, err
			}
			if _, ok := state[p.ID]; !ok {
				state[p.ID] = &NameKindEntry{Proposal: p, Status: ProposalPending}
			}
		case "name_kind_outcome":
			var o NameKindOutcome
			if err := json.Unmarshal(rec.Data, &o); err != nil {
				return nil, err
			}
			if e, ok := state[o.ProposalID]; ok {
				e.Status, e.Outcome = o.Status, &o
			}
		case "name_kind_advice":
			var a NameKindAdvice
			if err := json.Unmarshal(rec.Data, &a); err != nil {
				return nil, err
			}
			if e, ok := state[a.ProposalID]; ok {
				e.Advice = &a
			}
		}
	}

	r := readRedirects(lines)
	for _, e := range state {
		if e.Status == ProposalPending {
			r.redirected(&e.Proposal.RecordID)
		}
	}
	return state, nil
}

// NameKindEntries lists the journal's name proposals, pending first, then
// by name (NameKindGroup, so a group's proposals are together).
func (j *Journal) NameKindEntries() ([]NameKindEntry, error) {
	state, err := j.NameKindState()
	if err != nil {
		return nil, err
	}

	out := make([]NameKindEntry, 0, len(state))
	for _, e := range state {
		out = append(out, *e)
	}
	sort.Slice(out, func(a, b int) bool {
		pa, pb := out[a].Status == ProposalPending, out[b].Status == ProposalPending
		if pa != pb {
			return pa
		}
		if ga, gb := out[a].Proposal.Group(), out[b].Proposal.Group(); ga != gb {
			return ga < gb
		}
		return out[a].Proposal.ID < out[b].Proposal.ID
	})
	return out, nil
}

// FormatNameKindEntries renders name proposals for review. The pending
// proposals of one name in one field (NameKindGroup) are one entry, under
// the first one's ID, since deciding it decides them all.
func FormatNameKindEntries(entries []NameKindEntry) string {
	if len(entries) == 0 {
		return "No names awaiting a kind in the journal.\n"
	}

	groups := map[string][]NameKindEntry{}
	for _, e := range entries {
		if e.Status == ProposalPending {
			groups[e.Proposal.Group()] = append(groups[e.Proposal.Group()], e)
		}
	}

	var b strings.Builder
	shown := map[string]bool{}
	for _, e := range entries {
		p := e.Proposal
		group := groups[p.Group()]
		if e.Status == ProposalPending {
			if shown[p.Group()] {
				continue
			}
			shown[p.Group()] = true
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}

		fmt.Fprintf(&b, "%s  %s\n", p.ID, strings.ToUpper(e.Status))
		fmt.Fprintf(&b, "  is %q a person or an organization? %s [%s] names it as its %s", p.Name, p.RecordType,
			p.RecordID, p.Label)
		if p.Source != "" {
			fmt.Fprintf(&b, " (%s)", p.Source)
		}
		b.WriteString("\n")
		if e.Status == ProposalPending && len(group) > 1 {
			var more []string
			for _, g := range group[1:] {
				more = append(more, fmt.Sprintf("%s [%s] (%s)", g.Proposal.RecordType, g.Proposal.RecordID, g.Proposal.ID))
			}
			fmt.Fprintf(&b, "  and %d more, decided with it (-only for just this one): %s\n", len(more),
				strings.Join(more, ", "))
		}
		if len(p.Reasons) > 0 {
			fmt.Fprintf(&b, "  evidence: %s\n", strings.Join(p.Reasons, "; "))
		}
		if a := groupAdvice(e, group); a != nil {
			fmt.Fprintf(&b, "  advice from %s: %s at confidence %d. %s\n", a.Model, a.Kind, a.Confidence, a.Reason)
		}
		if o := e.Outcome; o != nil {
			fmt.Fprintf(&b, "  %s by %s at %s", o.Status, o.Reviewer, o.At.Format(time.RFC3339))
			if o.Kind != "" {
				fmt.Fprintf(&b, " as %s [%s]", o.Kind, o.EntityID)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// pendingNameKind returns a recorded name proposal still awaiting a decision.
func (j *Journal) pendingNameKind(id string) (NameKindProposal, error) {
	state, err := j.NameKindState()
	if err != nil {
		return NameKindProposal{}, err
	}
	e, ok := state[id]
	if !ok {
		return NameKindProposal{}, fmt.Errorf("no name proposal %s in the journal", id)
	}
	if e.Status != ProposalPending {
		return NameKindProposal{}, fmt.Errorf("name proposal %s is already %s", id, e.Status)
	}
	return e.Proposal, nil
}

// ApplyNameKind decides a pending name proposal as kind: it writes the
// Person or Organization linked from the record and records the decision.
func ApplyNameKind(ctx context.Context, w NameKindApplier, j *Journal, id, kind, reviewer string, confidence int,
	reason string) (NameKindOutcome, error) {
	if kind != NameKindPerson && kind != NameKindOrganization {
		return NameKindOutcome{}, fmt.Errorf("a name is decided as %s or %s, not %q", NameKindPerson,
			NameKindOrganization, kind)
	}
	if reviewer == "" {
		return NameKindOutcome{}, errors.New("reviewer required")
	}
	p, err := j.pendingNameKind(id)
	if err != nil {
		return NameKindOutcome{}, err
	}

	o, err := w.ApplyNameKind(ctx, p, kind, confidence)
	if err != nil {
		return o, fmt.Errorf("write %q as %s: %w", p.Name, kind, err)
	}
	o.ProposalID, o.Status, o.Reviewer, o.Kind, o.Confidence, o.Reason = id, ProposalApplied, reviewer, kind,
		confidence, reason
	if err := j.RecordNameKind(o); err != nil {
		return o, fmt.Errorf("%q was written as %s but the journal was not updated: %w", p.Name, kind, err)
	}
	return o, nil
}

// RejectNameKind records that a pending name names neither a person nor an
// organization the reviewer can tell; the raw name stays on its record.
func RejectNameKind(j *Journal, id, reviewer string) error {
	if _, err := j.pendingNameKind(id); err != nil {
		return err
	}
	return j.RecordNameKind(NameKindOutcome{ProposalID: id, Status: ProposalRejected, Reviewer: reviewer})
}

// RetractNameKind undoes an applied name proposal: the record it wrote is
// removed (the entity too when the decision created it and nothing else
// uses it) and the raw name is kept on its record again.
func RetractNameKind(ctx context.Context, w NameKindApplier, j *Journal, id, reviewer string) error {
	state, err := j.NameKindState()
	if err != nil {
		return err
	}
	e, ok := state[id]
	if !ok || e.Status != ProposalApplied || e.Outcome == nil {
		return fmt.Errorf("name proposal %s is not applied", id)
	}
	if err := w.RetractNameKind(ctx, e.Proposal, *e.Outcome); err != nil {
		return err
	}
	return j.RecordNameKind(NameKindOutcome{ProposalID: id, Status: ProposalRetracted, Reviewer: reviewer})
}

// groupAdvice is the advice shown for a pending entry: its own, or else the
// latest any proposal of its group has.
func groupAdvice(e NameKindEntry, group []NameKindEntry) *NameKindAdvice {
	if e.Status != ProposalPending {
		return nil
	}
	if e.Advice != nil {
		return e.Advice
	}

	var latest *NameKindAdvice
	for _, g := range group {
		if g.Advice != nil && (latest == nil || g.Advice.At.After(latest.At)) {
			latest = g.Advice
		}
	}
	return latest
}
