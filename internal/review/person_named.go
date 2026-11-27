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

// EntityRemoval records an entity (an Organization or a Person) removed
// from the Asset Database with its properties and relationships, so that it
// can be restored.
type EntityRemoval struct {
	// EntityID keeps the JSON key journals have always used.
	EntityID string `json:"organization_id"`
	// AssetType is the removed asset's type; empty is an Organization, as in
	// records written before people could be removed.
	AssetType string          `json:"asset_type,omitempty"`
	Asset     json.RawMessage `json:"asset"`
	Tags      []MergedTag     `json:"tags,omitempty"`
	Edges     []MergedEdge    `json:"edges"`
}

// EntityRemover removes an entity with its relationships and restores one
// from its record.
type EntityRemover interface {
	RemoveEntity(ctx context.Context, id string) (EntityRemoval, error)
	RestoreEntity(ctx context.Context, rec EntityRemoval) (string, error)
}

// PersonNamedOutcome records a decision on a person-named organization.
type PersonNamedOutcome struct {
	ProposalID string         `json:"proposal_id"`
	Status     string         `json:"status"`
	Reviewer   string         `json:"reviewer"`
	Record     *EntityRemoval `json:"record,omitempty"`
	RestoredID string         `json:"restored_id,omitempty"`
	At         time.Time      `json:"at"`
}

// PersonNamedEntry is a person-named organization proposal with its latest
// outcome.
type PersonNamedEntry struct {
	Proposal lens.PersonNamedOrg `json:"proposal"`
	Status   string              `json:"status"`
	Outcome  *PersonNamedOutcome `json:"outcome,omitempty"`
}

// SubmitPersonNamed records proposals not already in the journal.
func (j *Journal) SubmitPersonNamed(candidates []lens.PersonNamedOrg) ([]lens.PersonNamedOrg, error) {
	state, err := j.PersonNamedState()
	if err != nil {
		return nil, err
	}

	var added []lens.PersonNamedOrg
	for _, c := range candidates {
		if c.ID == "" || c.OrgID == "" {
			return added, errors.New("a person-named organization proposal needs an ID and an organization")
		}
		if _, ok := state[c.ID]; ok {
			continue
		}
		if c.CreatedAt.IsZero() {
			c.CreatedAt = time.Now().UTC()
		}
		if err := j.append("person_named_proposal", c); err != nil {
			return added, err
		}

		added = append(added, c)
	}

	return added, nil
}

// RecordPersonNamed records a decision on a person-named organization.
func (j *Journal) RecordPersonNamed(o PersonNamedOutcome) error {
	if o.ProposalID == "" || o.Reviewer == "" {
		return errors.New("proposal ID and reviewer required")
	}
	switch o.Status {
	case ProposalRejected, ProposalRetracted:
	case ProposalApplied:
		if o.Record == nil {
			return errors.New("an applied removal records what it removed")
		}
	default:
		return fmt.Errorf("invalid person-named status %q", o.Status)
	}

	o.At = time.Now().UTC()
	return j.append("person_named_outcome", o)
}

// PersonNamedState replays the journal into each proposal's current
// status. A missing journal is empty.
func (j *Journal) PersonNamedState() (map[string]*PersonNamedEntry, error) {
	state := map[string]*PersonNamedEntry{}
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
		case "person_named_proposal":
			var c lens.PersonNamedOrg
			if err := json.Unmarshal(rec.Data, &c); err != nil {
				return nil, err
			}
			if _, ok := state[c.ID]; !ok {
				state[c.ID] = &PersonNamedEntry{Proposal: c, Status: ProposalPending}
			}
		case "person_named_outcome":
			var o PersonNamedOutcome
			if err := json.Unmarshal(rec.Data, &o); err != nil {
				return nil, err
			}
			if e, ok := state[o.ProposalID]; ok {
				e.Status, e.Outcome = o.Status, &o
			}
		}
	}

	// pending proposals reach the records merges moved them to
	r := readRedirects(lines)
	for _, e := range state {
		if e.Status != ProposalPending {
			continue
		}
		r.redirected(&e.Proposal.OrgID, &e.Proposal.PersonID)
		for i := range e.Proposal.ContactIDs {
			r.redirected(&e.Proposal.ContactIDs[i])
		}
	}

	return state, nil
}

// PersonNamedEntries lists the journal's person-named organization
// proposals, pending first.
func (j *Journal) PersonNamedEntries() ([]PersonNamedEntry, error) {
	state, err := j.PersonNamedState()
	if err != nil {
		return nil, err
	}

	out := make([]PersonNamedEntry, 0, len(state))
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

// FormatPersonNamedEntries renders person-named organization proposals for
// review.
func FormatPersonNamedEntries(entries []PersonNamedEntry) string {
	if len(entries) == 0 {
		return "No person-named organizations in the journal.\n"
	}

	var b strings.Builder
	for i, e := range entries {
		if i > 0 {
			b.WriteString("\n")
		}

		p := e.Proposal
		fmt.Fprintf(&b, "%s  %s\n", p.ID, strings.ToUpper(e.Status))
		fmt.Fprintf(&b, "  remove organization %q [%s]: the registration contact also names the person %q [%s]",
			p.Organization, p.OrgID, p.Person, p.PersonID)
		if len(p.Domains) > 0 {
			fmt.Fprintf(&b, " (%s)", strings.Join(p.Domains, ", "))
		}
		b.WriteString("\n")
		if o := e.Outcome; o != nil {
			fmt.Fprintf(&b, "  %s by %s at %s\n", o.Status, o.Reviewer, o.At.Format(time.RFC3339))
		}
	}

	return b.String()
}

// ApplyPersonNamedRemoval removes a pending proposal's organization and
// records what was removed.
func ApplyPersonNamedRemoval(ctx context.Context, r EntityRemover, j *Journal, p lens.PersonNamedOrg,
	reviewer string) (EntityRemoval, error) {
	rec, err := r.RemoveEntity(ctx, p.OrgID)
	if err != nil {
		return rec, fmt.Errorf("remove %s [%s]: %w", p.Organization, p.OrgID, err)
	}
	if err := j.RecordPersonNamed(PersonNamedOutcome{ProposalID: p.ID, Status: ProposalApplied,
		Reviewer: reviewer, Record: &rec}); err != nil {
		return rec, fmt.Errorf("%s was removed but the journal was not updated: %w", p.Organization, err)
	}

	return rec, nil
}
