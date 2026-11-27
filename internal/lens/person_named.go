// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// PersonNamedPrefix starts the ID of a proposal to remove an organization
// that is a person's name.
const PersonNamedPrefix = "pno-"

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
	// CreatedAt is when the proposal was recorded; zero on records written
	// before it was kept.
	CreatedAt time.Time `json:"created_at,omitempty"`
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
	graph  graph.Graph
	report PersonNamedReport
	batch  batchAssets
}

// spend counts one database read; the search has no read budget.
func (s *personNamedSearch) spend() bool {
	s.report.Reads++
	return true
}

func (s *personNamedSearch) asset(id string) (graph.Asset, error) {
	if a, ok := s.batch.get(id); ok {
		return a, nil
	}

	s.spend()
	return s.graph.GetAsset(s.ctx, id)
}

func (s *personNamedSearch) edges(id, dir, label string) ([]graph.Relation, error) {
	edges, _, err := graph.ReadEdges(s.ctx, s.graph, id, dir, label, 0, s.spend)
	return edges, err
}

// FindPersonNamedOrganizations checks the stored organizations without a
// legal identity for ones recorded under a person's name. It reads only.
func FindPersonNamedOrganizations(ctx context.Context, g graph.Graph) (PersonNamedReport, error) {
	s := &personNamedSearch{ctx: ctx, graph: g}
	// Audit every organization that has no legal identity, a page at a time
	// when the repository can.
	err := walkType(ctx, g, "Organization", typePageSize,
		func(o graph.Asset) (bool, error) {
			if graph.ContentString(o, "legal_name") != "" || graph.ContentString(o, "jurisdiction") != "" ||
				graph.ContentString(o, "registration_id") != "" {
				return false, nil
			}

			s.report.Organizations++
			c, err := s.check(o)
			if err != nil {
				return false, err
			}
			if c != nil {
				s.report.Candidates = append(s.report.Candidates, *c)
			}

			return false, nil
		})
	if err != nil {
		return s.report, err
	}

	sort.Slice(s.report.Candidates, func(i, j int) bool {
		return s.report.Candidates[i].Organization < s.report.Candidates[j].Organization
	})
	return s.report, nil
}

// check reports an organization whose contact records name a Person with
// its name and are all domain registration contacts.
func (s *personNamedSearch) check(o graph.Asset) (*PersonNamedOrg, error) {
	name := personNameKey(graph.AssetLabel(o))
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
		if err := s.batch.load(s.ctx, s.graph, people, "out", s.spend); err != nil {
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
					Organization: graph.AssetLabel(o), PersonID: person.ID, Person: personFullName(person)}
			}
		}
		if found != nil {
			graph.AddUnique(&found.ContactIDs, c.FromID)
			for _, d := range domains {
				graph.AddUnique(&found.Domains, d)
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
		graph.AddUnique(&found.ContactIDs, c.FromID)
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

	if err := s.batch.load(s.ctx, s.graph, in, "in", s.spend); err != nil {
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
		if d := graph.ContentString(src, "domain"); d != "" {
			graph.AddUnique(&domains, strings.ToLower(d))
		}
	}

	return domains, nil
}

func personFullName(p graph.Asset) string {
	if n := graph.ContentString(p, "full_name"); n != "" {
		return n
	}

	first, last := graph.ContentString(p, "first_name"), graph.ContentString(p, "family_name")
	return strings.TrimSpace(first + " " + last)
}

// personNameKey compares names whatever their case, punctuation and word
// order ("Doe, Jane" and "jane doe"). A single word is not
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
