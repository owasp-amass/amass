// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/aitest"
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
	"github.com/owasp-amass/amass/v5/internal/ai/lens"
)

// personNamedGraph has an organization stored from a WHOIS registrant with
// no organization, its contact naming the person too; a company whose
// contact names a different person; a person-named organization that a
// network registry also names (a sole proprietor can hold a network); and
// one with a legal identity.
func personNamedGraph() aitest.FakeGraph {
	g := aitest.NewOrgGraph()
	a := func(id, typ string, content map[string]any) {
		g.Graph.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	registrant := func(domain, cr, org, person, personName string) {
		a("dr-"+domain, "DomainRecord", map[string]any{"domain": domain})
		a(cr, "ContactRecord", nil)
		g.Link("dr-"+domain, cr, "registrant_contact")
		g.Link(cr, org, "organization")
		if person != "" {
			a(person, "Person", map[string]any{"full_name": personName})
			g.Link(cr, person, "person")
		}
	}

	g.Org("eric", "eric torgersen", "", "", "")
	registrant("torgersen.example", "cr-eric", "eric", "p-eric", "Torgersen, Eric")

	g.Org("acme", "acme widgets", "", "", "")
	registrant("acme.example", "cr-acme", "acme", "p-jane", "Jane Doe")

	g.Org("smith", "john smith", "", "", "")
	registrant("smith.example", "cr-smith", "smith", "p-smith", "John Smith")
	a("ipnet", "IPNetRecord", map[string]any{"cidr": "192.0.2.0/24"})
	g.Link("ipnet", "cr-smith", "registrant")

	g.Org("legal", "ralph lauren", "ralph lauren corporation", "US-DE", "1")
	registrant("rl.example", "cr-rl", "legal", "p-rl", "Ralph Lauren")

	return g.Graph
}

func TestFindPersonNamedOrganizations(t *testing.T) {
	r, err := lens.FindPersonNamedOrganizations(context.Background(), personNamedGraph())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Candidates) != 1 {
		t.Fatalf("candidates = %+v", r.Candidates)
	}
	c := r.Candidates[0]
	if c.OrgID != "eric" || c.PersonID != "p-eric" || strings.Join(c.Domains, ",") != "torgersen.example" ||
		!strings.HasPrefix(c.ID, lens.PersonNamedPrefix) {
		t.Errorf("candidate = %+v", c)
	}
	if r.Organizations != 3 {
		t.Errorf("checked %d organizations without a legal identity, want 3", r.Organizations)
	}

	j := &Journal{Path: filepath.Join(t.TempDir(), "journal.jsonl")}
	added, err := j.SubmitPersonNamed(r.Candidates)
	if err != nil || len(added) != 1 {
		t.Fatalf("added %v, %v", added, err)
	}
	if again, _ := j.SubmitPersonNamed(r.Candidates); len(again) != 0 {
		t.Error("a proposal was recorded twice")
	}
	entries, err := j.PersonNamedEntries()
	if err != nil || len(entries) != 1 || entries[0].Status != ProposalPending ||
		!strings.Contains(FormatPersonNamedEntries(entries), `remove organization "eric torgersen"`) {
		t.Errorf("entries = %+v, %v", entries, err)
	}
}
