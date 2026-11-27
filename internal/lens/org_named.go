// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// OrgNamedPrefix starts the ID of a proposal to convert a Person that is an
// organization's name into an Organization.
const OrgNamedPrefix = "onp-"

// OrgNamedPerson is a Person stored under an organization's name, as when a
// document's Author or a registry contact gave the organization: the name
// rules (semantics.NameKindOf) find organization evidence, such as a legal
// form, an institution word or the contact record's own organization, and
// no person evidence.
type OrgNamedPerson struct {
	ID       string `json:"id"`
	PersonID string `json:"person_id"`
	Person   string `json:"person"`
	// Reasons are what the name rules weighed.
	Reasons []string `json:"reasons"`
	// ContactIDs are the contact records naming the person.
	ContactIDs []string `json:"contact_ids,omitempty"`
	// OrgID is an Organization with the name that one of those records
	// names as its organization, which the conversion reuses; empty means
	// the conversion creates one.
	OrgID string `json:"org_id,omitempty"`
	// Advice is the trained name-kind classifier's answer when the proposal
	// was recorded, if it had one and was sure; never applied.
	Advice *NameKindAdvice `json:"advice,omitempty"`
	// CreatedAt is when the proposal was recorded.
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// NameKindAdvice is a classifier's answer to whether a name is a person's or
// an organization's.
type NameKindAdvice struct {
	Model      string `json:"model"`
	Kind       string `json:"kind"`
	Confidence int    `json:"confidence"`
}

// OrgNamedReport is the result of the organization-named person check.
type OrgNamedReport struct {
	Persons    int              `json:"persons"`
	Candidates []OrgNamedPerson `json:"candidates"`
	Reads      int              `json:"reads"`
	Truncated  bool             `json:"truncated"`
	Reason     string           `json:"reason,omitempty"`
}

// OrgNamedID is a stable identifier for converting one person.
func OrgNamedID(personID string) string {
	sum := sha256.Sum256([]byte("onp\x00" + personID))
	return OrgNamedPrefix + hex.EncodeToString(sum[:8])
}

// FindOrgNamedPersons checks the stored people for ones recorded under an
// organization's name. It reads only.
func FindOrgNamedPersons(ctx context.Context, g graph.Graph) (OrgNamedReport, error) {
	var report OrgNamedReport
	s := &personNamedSearch{ctx: ctx, graph: g}
	err := walkType(ctx, g, "Person", typePageSize,
		func(p graph.Asset) (bool, error) {
			report.Persons++
			c, err := checkOrgNamed(s, p)
			if err != nil {
				return false, err
			}
			if c != nil {
				report.Candidates = append(report.Candidates, *c)
			}
			return false, nil
		})
	report.Reads = s.report.Reads
	if err != nil {
		return report, err
	}

	sort.Slice(report.Candidates, func(i, j int) bool { return report.Candidates[i].Person < report.Candidates[j].Person })
	return report, nil
}

// checkOrgNamed reports a person whose name the name rules say is an
// organization's, given what its contact records say.
func checkOrgNamed(s *personNamedSearch, p graph.Asset) (*OrgNamedPerson, error) {
	name := strings.TrimSpace(personFullName(p))
	if name == "" {
		return nil, nil
	}

	clues := semantics.NameClues{First: graph.ContentString(p, "first_name"),
		Middle: graph.ContentString(p, "middle_name"), Last: graph.ContentString(p, "family_name")}
	c := &OrgNamedPerson{ID: OrgNamedID(p.ID), PersonID: p.ID, Person: name}
	orgByKey := map[string]string{}

	contacts, err := s.edges(p.ID, "in", "person")
	if err != nil {
		return nil, err
	}
	for _, rel := range contacts {
		graph.AddUnique(&c.ContactIDs, rel.FromID)
		for _, label := range []string{"organization", "email"} {
			out, err := s.edges(rel.FromID, "out", label)
			if err != nil {
				return nil, err
			}
			for _, o := range out {
				a, err := s.asset(o.ToID)
				if err != nil {
					return nil, err
				}
				if label == "email" {
					clues.Emails = append(clues.Emails, graph.AssetLabel(a))
					continue
				}
				orgName := graph.AssetLabel(a)
				clues.OrgNames = append(clues.OrgNames, orgName)
				if key := semantics.OrgNameKey(orgName); key != "" {
					orgByKey[key] = a.ID
				}
			}
		}
	}

	kind, reasons := semantics.NameKindOf(name, clues)
	if kind != semantics.NameKindOrganization {
		return nil, nil
	}
	c.Reasons = reasons
	c.OrgID = orgByKey[semantics.OrgNameKey(name)]
	sort.Strings(c.ContactIDs)
	return c, nil
}

// FormatOrgNamedReport renders the organization-named person check for a
// terminal.
func FormatOrgNamedReport(r OrgNamedReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Checked %d people (%d reads).", r.Persons, r.Reads)
	if r.Truncated {
		fmt.Fprintf(&b, " Incomplete: %s.", r.Reason)
	}

	b.WriteString("\n")
	if len(r.Candidates) == 0 {
		b.WriteString("No person is recorded under an organization's name.\n")
		return b.String()
	}

	b.WriteString("These people are an organization's name: the name rules find organization evidence and no " +
		"person evidence.\n")
	for _, c := range r.Candidates {
		fmt.Fprintf(&b, "\n%s [%s]: %s\n", c.Person, c.PersonID, strings.Join(c.Reasons, "; "))
	}
	return b.String()
}
