// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"sort"
	"strings"
)

// NameKindGroup is the key name proposals decided together share: the same
// name, case and spacing aside, in the same field ("jgordon" as the author
// of five files). Whether a name is a person's or an organization's does not
// change from record to record.
func NameKindGroup(label, name string) string {
	return strings.ToLower(strings.TrimSpace(label)) + "|" + strings.ToLower(strings.Join(strings.Fields(name), " "))
}

// Group is the proposal's NameKindGroup.
func (p NameKindProposal) Group() string { return NameKindGroup(p.Label, p.Name) }

// pendingNameKindGroup returns the pending proposals of p's group, p first
// and then by when they were recorded, as they now stand.
func pendingNameKindGroup(state map[string]*NameKindEntry, p NameKindProposal) []NameKindProposal {
	group := []NameKindProposal{p}
	var rest []NameKindProposal
	for _, e := range state {
		if e.Status == ProposalPending && e.Proposal.ID != p.ID && e.Proposal.Group() == p.Group() {
			rest = append(rest, e.Proposal)
		}
	}
	sort.Slice(rest, func(a, b int) bool {
		if !rest[a].CreatedAt.Equal(rest[b].CreatedAt) {
			return rest[a].CreatedAt.Before(rest[b].CreatedAt)
		}
		return rest[a].ID < rest[b].ID
	})
	return append(group, rest...)
}

// UnansweredNameKindGroup returns the pending proposals of p's group, p
// among them, that have no answer yet, as they now stand, so one answer
// covers them all.
func (j *Journal) UnansweredNameKindGroup(p NameKindProposal) ([]NameKindProposal, error) {
	state, err := j.NameKindState()
	if err != nil {
		return nil, err
	}

	var out []NameKindProposal
	for _, g := range pendingNameKindGroup(state, p) {
		if e := state[g.ID]; e != nil && e.Status == ProposalPending && e.Advice == nil {
			out = append(out, e.Proposal)
		}
	}
	return out, nil
}

// NameKindGroupAnswer returns the latest answer another proposal of p's
// group was given, as an answer for p: a decision that stands (a person's or
// an automatic one, with its confidence; a person decides at 100) or a
// model's advice. ok is false when no other proposal of the group has one,
// and p must be asked.
func (j *Journal) NameKindGroupAnswer(p NameKindProposal) (a NameKindAdvice, ok bool, err error) {
	state, err := j.NameKindState()
	if err != nil {
		return NameKindAdvice{}, false, err
	}

	for id, e := range state {
		if id == p.ID || e.Proposal.Group() != p.Group() {
			continue
		}
		var c NameKindAdvice
		switch {
		case e.Status == ProposalApplied && e.Outcome != nil:
			o := e.Outcome
			c = NameKindAdvice{Model: o.Reviewer, Kind: o.Kind, Confidence: o.Confidence, At: o.At,
				Reason: groupReason("decided for", id, o.Reason)}
		case e.Status == ProposalPending && e.Advice != nil:
			c = *e.Advice
			c.Reason = groupReason("answered for", id, c.Reason)
		default:
			continue
		}
		if !ok || c.At.After(a.At) {
			a, ok = c, true
		}
	}
	a.ProposalID = p.ID
	return a, ok, nil
}

// sameNameField ends the note that an answer was given for another proposal
// of the group.
const sameNameField = ", the same name in the same field"

// groupReason notes that reason was given for proposal id of the same group.
// A reason that already names the proposal it was first given for (copied
// from one proposal to the next) keeps that note alone.
func groupReason(verb, id, reason string) string {
	if (strings.HasPrefix(reason, "answered for ") || strings.HasPrefix(reason, "decided for ")) &&
		strings.Contains(reason, sameNameField) {
		return reason
	}
	if reason == "" {
		return verb + " " + id + sameNameField
	}
	return verb + " " + id + sameNameField + ": " + reason
}

// ApplyNameKindGroup decides the pending proposal id as kind, and with it
// every pending proposal of its group unless only is set, each recorded on
// its own so any one can be retracted. It returns the outcomes in order,
// stopping at the first failure.
func ApplyNameKindGroup(ctx context.Context, w NameKindApplier, j *Journal, id, kind, reviewer string,
	confidence int, reason string, only bool) ([]NameKindOutcome, error) {
	ids, err := j.nameKindGroupIDs(id, only)
	if err != nil {
		return nil, err
	}

	var out []NameKindOutcome
	for _, gid := range ids {
		o, err := ApplyNameKind(ctx, w, j, gid, kind, reviewer, confidence, reason)
		if err != nil {
			return out, err
		}
		out = append(out, o)
	}
	return out, nil
}

// RejectNameKindGroup rejects the pending proposal id, and with it every
// pending proposal of its group unless only is set. It returns the rejected
// IDs.
func RejectNameKindGroup(j *Journal, id, reviewer string, only bool) ([]string, error) {
	ids, err := j.nameKindGroupIDs(id, only)
	if err != nil {
		return nil, err
	}

	for i, gid := range ids {
		if err := RejectNameKind(j, gid, reviewer); err != nil {
			return ids[:i], err
		}
	}
	return ids, nil
}

// nameKindGroupIDs returns the pending proposal id, then the rest of its
// group's pending proposals unless only is set.
func (j *Journal) nameKindGroupIDs(id string, only bool) ([]string, error) {
	p, err := j.pendingNameKind(id)
	if err != nil {
		return nil, err
	}
	if only {
		return []string{id}, nil
	}

	state, err := j.NameKindState()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, g := range pendingNameKindGroup(state, p) {
		ids = append(ids, g.ID)
	}
	return ids, nil
}
