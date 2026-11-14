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
	"os"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
)

// PersonNamedPrefix starts the ID of a proposal to remove an organization
// that is a person's name.
const PersonNamedPrefix = "pno-"

// Person-named organization search bounds.
const (
	personNamedMaxReads    = 50000
	personNamedMaxContacts = 50
)

// PersonNamedOrg is an organization recorded under a person's name: one of
// its own contact records names a Person with the same full name, it has no
// legal identity, and only domain registration records name it, as when a
// WHOIS contact with no organization was stored with the person's name as
// one.
type PersonNamedOrg struct {
	ID           string   `json:"id"`
	OrgID        string   `json:"org_id"`
	Organization string   `json:"organization"`
	PersonID     string   `json:"person_id"`
	Person       string   `json:"person"`
	ContactIDs   []string `json:"contact_ids"`
	Domains      []string `json:"domains,omitempty"`
}

// PersonNamedReport is the result of the person-named organization check.
type PersonNamedReport struct {
	Organizations int              `json:"organizations"`
	Candidates    []PersonNamedOrg `json:"candidates"`
	Reads         int              `json:"reads"`
	Truncated     bool             `json:"truncated"`
	Reason        string           `json:"reason,omitempty"`
}

// PersonNamedID is a stable identifier for removing one organization.
func PersonNamedID(orgID, personID string) string {
	sum := sha256.Sum256([]byte(orgID + "\x00" + personID))
	return PersonNamedPrefix + hex.EncodeToString(sum[:8])
}

type personNamedSearch struct {
	ctx    context.Context
	graph  Graph
	report PersonNamedReport
}

func (s *personNamedSearch) spend() bool {
	if s.report.Reads >= personNamedMaxReads {
		return false
	}

	s.report.Reads++
	return true
}

func (s *personNamedSearch) asset(id string) (Asset, error) {
	if !s.spend() {
		return Asset{}, errDupReadLimit
	}

	return s.graph.GetAsset(s.ctx, id)
}

func (s *personNamedSearch) edges(id, dir, label string) ([]Relation, error) {
	edges, _, err := readEdges(s.ctx, s.graph, id, dir, label, personNamedMaxContacts, s.spend)
	if errors.Is(err, errDupReadLimit) || (err == nil && s.report.Reads >= personNamedMaxReads) {
		return edges, errDupReadLimit
	}

	return edges, err
}

// FindPersonNamedOrganizations checks the stored organizations without a
// legal identity for ones recorded under a person's name. It reads only.
func FindPersonNamedOrganizations(ctx context.Context, graph Graph) (PersonNamedReport, error) {
	s := &personNamedSearch{ctx: ctx, graph: graph}
	orgs, err := graph.FindAssets(ctx, "Organization", time.Time{}, dupMaxOrganizations+1)
	if err != nil {
		return s.report, err
	}
	if len(orgs) > dupMaxOrganizations {
		orgs = orgs[:dupMaxOrganizations]
		s.report.Truncated, s.report.Reason = true, fmt.Sprintf("more than %d organizations", dupMaxOrganizations)
	}

	for _, o := range orgs {
		if contentString(o, "legal_name") != "" || contentString(o, "jurisdiction") != "" ||
			contentString(o, "registration_id") != "" {
			continue
		}

		s.report.Organizations++
		c, err := s.check(o)
		if errors.Is(err, errDupReadLimit) {
			s.report.Truncated, s.report.Reason = true, err.Error()
			break
		} else if err != nil {
			return s.report, err
		}
		if c != nil {
			s.report.Candidates = append(s.report.Candidates, *c)
		}
	}

	sort.Slice(s.report.Candidates, func(i, j int) bool {
		return s.report.Candidates[i].Organization < s.report.Candidates[j].Organization
	})
	return s.report, nil
}

// check reports an organization whose contact records name a Person with
// its name and are all domain registration contacts.
func (s *personNamedSearch) check(o Asset) (*PersonNamedOrg, error) {
	name := personNameKey(assetLabel(o))
	if name == "" {
		return nil, nil
	}

	contacts, err := s.edges(o.ID, "in", "organization")
	if err != nil || len(contacts) == 0 {
		return nil, err
	}

	var found *PersonNamedOrg
	for _, c := range contacts {
		// Every record naming the organization must be a domain registration's
		// contact: a network registry or certificate naming it is other
		// evidence that it is an organization.
		domains, err := s.registrationDomains(c.FromID)
		if err != nil {
			return nil, err
		}
		if len(domains) == 0 {
			return nil, nil
		}

		people, err := s.edges(c.FromID, "out", "person")
		if err != nil {
			return nil, err
		}
		for _, p := range people {
			person, err := s.asset(p.ToID)
			if err != nil {
				return nil, err
			}
			if personNameKey(personFullName(person)) != name {
				continue
			}

			if found == nil {
				found = &PersonNamedOrg{ID: PersonNamedID(o.ID, person.ID), OrgID: o.ID,
					Organization: assetLabel(o), PersonID: person.ID, Person: personFullName(person)}
			}
		}
		if found != nil {
			addUnique(&found.ContactIDs, c.FromID)
			for _, d := range domains {
				addUnique(&found.Domains, d)
			}
		}
	}
	if found == nil {
		return nil, nil
	}

	// The contacts that do not name the person still count as the
	// organization's, and they too must be registration contacts, as checked
	// above.
	for _, c := range contacts {
		addUnique(&found.ContactIDs, c.FromID)
	}
	sort.Strings(found.ContactIDs)
	sort.Strings(found.Domains)
	return found, nil
}

// registrationDomains returns the domains whose registration records name
// the contact record, or none when anything other than a domain
// registration record points at it.
func (s *personNamedSearch) registrationDomains(contactID string) ([]string, error) {
	in, err := s.edges(contactID, "in", "")
	if err != nil {
		return nil, err
	}

	var domains []string
	for _, e := range in {
		src, err := s.asset(e.FromID)
		if err != nil {
			return nil, err
		}
		if src.Type != "DomainRecord" {
			return nil, nil
		}
		if d := contentString(src, "domain"); d != "" {
			addUnique(&domains, strings.ToLower(d))
		}
	}

	return domains, nil
}

func personFullName(p Asset) string {
	if n := contentString(p, "full_name"); n != "" {
		return n
	}

	first, last := contentString(p, "first_name"), contentString(p, "family_name")
	return strings.TrimSpace(first + " " + last)
}

// personNameKey compares names whatever their case, punctuation and word
// order ("Torgersen, Eric" and "eric torgersen"). A single word is not
// enough to say a name is a person's.
func personNameKey(name string) string {
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return !unicode.IsLetter(r) && r != '\''
	})
	if len(words) < 2 {
		return ""
	}

	slices.Sort(words)
	return strings.Join(words, " ")
}

// OrganizationRemoval records an organization removed from the Asset
// Database, so that it can be restored.
type OrganizationRemoval struct {
	OrganizationID string          `json:"organization_id"`
	Asset          json.RawMessage `json:"asset"`
	Tags           []MergedTag     `json:"tags,omitempty"`
	Edges          []MergedEdge    `json:"edges"`
}

// OrganizationRemover removes an organization with its relationships and
// restores one from its record.
type OrganizationRemover interface {
	RemoveOrganization(ctx context.Context, id string) (OrganizationRemoval, error)
	RestoreOrganization(ctx context.Context, rec OrganizationRemoval) (string, error)
}

// PersonNamedOutcome records a decision on a person-named organization.
type PersonNamedOutcome struct {
	ProposalID string               `json:"proposal_id"`
	Status     string               `json:"status"`
	Reviewer   string               `json:"reviewer"`
	Record     *OrganizationRemoval `json:"record,omitempty"`
	RestoredID string               `json:"restored_id,omitempty"`
	At         time.Time            `json:"at"`
}

// PersonNamedEntry is a person-named organization proposal with its latest
// outcome.
type PersonNamedEntry struct {
	Proposal PersonNamedOrg      `json:"proposal"`
	Status   string              `json:"status"`
	Outcome  *PersonNamedOutcome `json:"outcome,omitempty"`
}

// SubmitPersonNamed records proposals not already in the journal.
func (j *Journal) SubmitPersonNamed(candidates []PersonNamedOrg) ([]PersonNamedOrg, error) {
	state, err := j.PersonNamedState()
	if err != nil {
		return nil, err
	}

	var added []PersonNamedOrg
	for _, c := range candidates {
		if c.ID == "" || c.OrgID == "" {
			return added, errors.New("a person-named organization proposal needs an ID and an organization")
		}
		if _, ok := state[c.ID]; ok {
			continue
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
			var c PersonNamedOrg
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

// FormatPersonNamedReport renders the person-named organization check for a
// terminal.
func FormatPersonNamedReport(r PersonNamedReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Checked %d organizations without a legal identity (%d reads).", r.Organizations, r.Reads)
	if r.Truncated {
		fmt.Fprintf(&b, " Incomplete: %s.", r.Reason)
	}
	b.WriteString("\n")
	if len(r.Candidates) == 0 {
		b.WriteString("No organization is recorded under a person's name.\n")
		return b.String()
	}

	b.WriteString("These organizations are a person's name: their registration contact also names the person, " +
		"and nothing but domain registrations names them.\n")
	for _, c := range r.Candidates {
		fmt.Fprintf(&b, "\n%s [%s]: the person %s [%s]", c.Organization, c.OrgID, c.Person, c.PersonID)
		if len(c.Domains) > 0 {
			fmt.Fprintf(&b, ", registration contact for %s", strings.Join(c.Domains, ", "))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// ApplyPersonNamedRemoval removes a pending proposal's organization and
// records what was removed.
func ApplyPersonNamedRemoval(ctx context.Context, r OrganizationRemover, j *Journal, p PersonNamedOrg,
	reviewer string) (OrganizationRemoval, error) {
	rec, err := r.RemoveOrganization(ctx, p.OrgID)
	if err != nil {
		return rec, fmt.Errorf("remove %s [%s]: %w", p.Organization, p.OrgID, err)
	}
	if err := j.RecordPersonNamed(PersonNamedOutcome{ProposalID: p.ID, Status: ProposalApplied,
		Reviewer: reviewer, Record: &rec}); err != nil {
		return rec, fmt.Errorf("%s was removed but the journal was not updated: %w", p.Organization, err)
	}

	return rec, nil
}
