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

// PersonConversion records a Person converted into an Organization: the
// removed Person, the Organization its relationships moved to, and what the
// conversion added, so that undoing it restores the Person exactly.
type PersonConversion struct {
	Person EntityRemoval `json:"person"`
	OrgID  string        `json:"org_id"`
	// OrgCreated reports whether the conversion created the Organization.
	OrgCreated bool `json:"org_created,omitempty"`
	// AddedEdges are the relationships the conversion created on the
	// Organization (one it already had is not among them). The Person's
	// properties are copied only to an Organization the conversion created,
	// so undoing it never touches an existing one's.
	AddedEdges []string `json:"added_edges,omitempty"`
	// Dropped are the Person's relationships an Organization cannot have;
	// they are kept here and come back with the Person.
	Dropped []MergedEdge `json:"dropped,omitempty"`
}

// PersonConverter converts a Person into an Organization and undoes it.
type PersonConverter interface {
	ConvertPersonToOrganization(ctx context.Context, p lens.OrgNamedPerson) (PersonConversion, error)
	// RevertPersonConversion returns the restored Person's ID.
	RevertPersonConversion(ctx context.Context, rec PersonConversion) (string, error)
}

// OrgNamedOutcome records a decision on an organization-named person.
type OrgNamedOutcome struct {
	ProposalID string            `json:"proposal_id"`
	Status     string            `json:"status"`
	Reviewer   string            `json:"reviewer"`
	Record     *PersonConversion `json:"record,omitempty"`
	RestoredID string            `json:"restored_id,omitempty"`
	At         time.Time         `json:"at"`
}

// OrgNamedEntry is an organization-named person proposal with its latest
// outcome.
type OrgNamedEntry struct {
	Proposal lens.OrgNamedPerson `json:"proposal"`
	Status   string              `json:"status"`
	Outcome  *OrgNamedOutcome    `json:"outcome,omitempty"`
}

// IsOrgNamedProposal reports whether id is an organization-named person
// proposal's.
func IsOrgNamedProposal(id string) bool { return strings.HasPrefix(id, lens.OrgNamedPrefix) }

// SubmitOrgNamed records proposals not already in the journal.
func (j *Journal) SubmitOrgNamed(candidates []lens.OrgNamedPerson) ([]lens.OrgNamedPerson, error) {
	state, err := j.OrgNamedState()
	if err != nil {
		return nil, err
	}

	var added []lens.OrgNamedPerson
	for _, c := range candidates {
		if c.ID == "" || c.PersonID == "" || strings.TrimSpace(c.Person) == "" {
			return added, errors.New("an organization-named person proposal needs an ID, a person and a name")
		}
		if _, ok := state[c.ID]; ok {
			continue
		}
		if c.CreatedAt.IsZero() {
			c.CreatedAt = time.Now().UTC()
		}
		if err := j.append("org_named_proposal", c); err != nil {
			return added, err
		}
		state[c.ID] = &OrgNamedEntry{Proposal: c, Status: ProposalPending}
		added = append(added, c)
	}
	return added, nil
}

// RecordOrgNamed records a decision on an organization-named person.
func (j *Journal) RecordOrgNamed(o OrgNamedOutcome) error {
	if o.ProposalID == "" || o.Reviewer == "" {
		return errors.New("proposal ID and reviewer required")
	}
	switch o.Status {
	case ProposalRejected, ProposalRetracted:
	case ProposalApplied:
		if o.Record == nil || o.Record.OrgID == "" {
			return errors.New("an applied conversion records what it changed")
		}
	default:
		return fmt.Errorf("invalid organization-named status %q", o.Status)
	}

	o.At = time.Now().UTC()
	return j.append("org_named_outcome", o)
}

// OrgNamedState replays the journal into each proposal's current status;
// pending proposals reach the records merges moved them to. A missing
// journal is empty.
func (j *Journal) OrgNamedState() (map[string]*OrgNamedEntry, error) {
	state := map[string]*OrgNamedEntry{}
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
		case "org_named_proposal":
			var c lens.OrgNamedPerson
			if err := json.Unmarshal(rec.Data, &c); err != nil {
				return nil, err
			}
			if _, ok := state[c.ID]; !ok {
				state[c.ID] = &OrgNamedEntry{Proposal: c, Status: ProposalPending}
			}
		case "org_named_outcome":
			var o OrgNamedOutcome
			if err := json.Unmarshal(rec.Data, &o); err != nil {
				return nil, err
			}
			if e, ok := state[o.ProposalID]; ok {
				e.Status, e.Outcome = o.Status, &o
			}
		}
	}

	r := readRedirects(lines)
	for _, e := range state {
		if e.Status != ProposalPending {
			continue
		}
		r.redirected(&e.Proposal.PersonID, &e.Proposal.OrgID)
		for i := range e.Proposal.ContactIDs {
			r.redirected(&e.Proposal.ContactIDs[i])
		}
	}
	return state, nil
}

// OrgNamedEntries lists the journal's organization-named person proposals,
// pending first, then by name.
func (j *Journal) OrgNamedEntries() ([]OrgNamedEntry, error) {
	state, err := j.OrgNamedState()
	if err != nil {
		return nil, err
	}

	out := make([]OrgNamedEntry, 0, len(state))
	for _, e := range state {
		out = append(out, *e)
	}
	sort.Slice(out, func(a, b int) bool {
		pa, pb := out[a].Status == ProposalPending, out[b].Status == ProposalPending
		if pa != pb {
			return pa
		}
		return out[a].Proposal.Person < out[b].Proposal.Person
	})
	return out, nil
}

// FormatOrgNamedEntries renders organization-named person proposals for
// review.
func FormatOrgNamedEntries(entries []OrgNamedEntry) string {
	if len(entries) == 0 {
		return "No people recorded under an organization's name in the journal.\n"
	}

	var b strings.Builder
	for i, e := range entries {
		if i > 0 {
			b.WriteString("\n")
		}
		p := e.Proposal
		fmt.Fprintf(&b, "%s  %s\n", p.ID, strings.ToUpper(e.Status))
		fmt.Fprintf(&b, "  convert the person %q [%s] into an organization", p.Person, p.PersonID)
		if p.OrgID != "" {
			fmt.Fprintf(&b, ": its contact record already names it [%s]", p.OrgID)
		}
		b.WriteString("\n")
		if len(p.Reasons) > 0 {
			fmt.Fprintf(&b, "  evidence: %s\n", strings.Join(p.Reasons, "; "))
		}
		if a := p.Advice; a != nil && e.Status == ProposalPending {
			fmt.Fprintf(&b, "  advice from %s: %s at confidence %d\n", a.Model, a.Kind, a.Confidence)
		}
		if o := e.Outcome; o != nil {
			fmt.Fprintf(&b, "  %s by %s at %s", o.Status, o.Reviewer, o.At.Format(time.RFC3339))
			if r := o.Record; r != nil && o.Status == ProposalApplied {
				fmt.Fprintf(&b, ": now organization [%s]", r.OrgID)
				if len(r.Dropped) > 0 {
					fmt.Fprintf(&b, "; %d relationship(s) an organization cannot have are kept for undo",
						len(r.Dropped))
				}
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// pendingOrgNamed returns a recorded proposal still awaiting a decision.
func (j *Journal) pendingOrgNamed(id string) (lens.OrgNamedPerson, error) {
	state, err := j.OrgNamedState()
	if err != nil {
		return lens.OrgNamedPerson{}, err
	}
	e, ok := state[id]
	if !ok {
		return lens.OrgNamedPerson{}, fmt.Errorf("no organization-named person proposal %s in the journal", id)
	}
	if e.Status != ProposalPending {
		return lens.OrgNamedPerson{}, fmt.Errorf("proposal %s is already %s", id, e.Status)
	}
	return e.Proposal, nil
}

// ApplyOrgNamed converts a pending proposal's person into an organization
// and records what changed.
func ApplyOrgNamed(ctx context.Context, w PersonConverter, j *Journal, id, reviewer string) (PersonConversion, error) {
	if reviewer == "" {
		return PersonConversion{}, errors.New("reviewer required")
	}
	p, err := j.pendingOrgNamed(id)
	if err != nil {
		return PersonConversion{}, err
	}

	rec, err := w.ConvertPersonToOrganization(ctx, p)
	if err != nil {
		return rec, fmt.Errorf("convert %q [%s]: %w", p.Person, p.PersonID, err)
	}
	if err := j.RecordOrgNamed(OrgNamedOutcome{ProposalID: id, Status: ProposalApplied, Reviewer: reviewer,
		Record: &rec}); err != nil {
		return rec, fmt.Errorf("%q was converted but the journal was not updated: %w", p.Person, err)
	}
	return rec, nil
}

// RejectOrgNamed records that a pending proposal's person is a person.
func RejectOrgNamed(j *Journal, id, reviewer string) error {
	if _, err := j.pendingOrgNamed(id); err != nil {
		return err
	}
	return j.RecordOrgNamed(OrgNamedOutcome{ProposalID: id, Status: ProposalRejected, Reviewer: reviewer})
}

// RetractOrgNamed undoes an applied conversion and returns the restored
// Person's ID.
func RetractOrgNamed(ctx context.Context, w PersonConverter, j *Journal, id, reviewer string) (string, error) {
	state, err := j.OrgNamedState()
	if err != nil {
		return "", err
	}
	e, ok := state[id]
	if !ok || e.Status != ProposalApplied || e.Outcome == nil || e.Outcome.Record == nil {
		return "", fmt.Errorf("proposal %s is not applied", id)
	}

	restored, err := w.RevertPersonConversion(ctx, *e.Outcome.Record)
	if err != nil {
		return "", err
	}
	return restored, j.RecordOrgNamed(OrgNamedOutcome{ProposalID: id, Status: ProposalRetracted,
		Reviewer: reviewer, RestoredID: restored})
}
