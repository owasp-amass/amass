// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// orgNamedGraph has a person stored under the organization its contact
// record names, one under a company's name whose record names another
// organization, and a person.
func orgNamedGraph() graphtest.FakeGraph {
	g := graphtest.NewOrgGraph()
	person := func(id, cr, name string) {
		g.Graph.Assets[id] = graph.Asset{ID: id, Type: "Person", Key: id, Content: map[string]any{"full_name": name}}
		g.Graph.Assets[cr] = graph.Asset{ID: cr, Type: "ContactRecord", Key: cr}
		g.Link(cr, id, "person")
	}

	g.Org("tw", "TAYLOR WESSING LLP", "", "", "")
	person("p-tw", "cr-tw", "Taylor Wessing LLP")
	g.Link("cr-tw", "tw", "organization")

	g.Org("acme", "acme widgets", "", "", "")
	person("p-mm", "cr-mm", "MarkMonitor, Inc.")
	g.Link("cr-mm", "acme", "organization")

	person("p-john", "cr-john", "John Smith")
	g.Link("cr-john", "acme", "organization")
	return g.Graph
}

func TestFindOrgNamedPersons(t *testing.T) {
	r, err := lens.FindOrgNamedPersons(context.Background(), orgNamedGraph())
	if err != nil {
		t.Fatal(err)
	}
	if r.Persons != 3 || len(r.Candidates) != 2 {
		t.Fatalf("checked %d people, candidates = %+v", r.Persons, r.Candidates)
	}

	byPerson := map[string]lens.OrgNamedPerson{}
	for _, c := range r.Candidates {
		byPerson[c.PersonID] = c
		if !strings.HasPrefix(c.ID, lens.OrgNamedPrefix) || len(c.Reasons) == 0 {
			t.Errorf("candidate = %+v", c)
		}
	}
	if c := byPerson["p-tw"]; c.OrgID != "tw" || strings.Join(c.ContactIDs, ",") != "cr-tw" {
		t.Errorf("the record's own organization is not reused: %+v", c)
	}
	if c, ok := byPerson["p-mm"]; !ok || c.OrgID != "" {
		t.Errorf("another organization on the record was reused: %+v", c)
	}
}

// fakeConverter records what was converted and reverted.
type fakeConverter struct {
	converted []string
	reverted  []PersonConversion
	fail      error
}

func (f *fakeConverter) ConvertPersonToOrganization(_ context.Context, p lens.OrgNamedPerson) (PersonConversion, error) {
	if f.fail != nil {
		return PersonConversion{}, f.fail
	}
	f.converted = append(f.converted, p.PersonID)
	return PersonConversion{
		Person:     EntityRemoval{EntityID: p.PersonID, AssetType: "Person"},
		OrgID:      "org-" + p.PersonID,
		OrgCreated: p.OrgID == "",
		AddedEdges: []string{"e1"},
		Dropped:    []MergedEdge{{}},
	}, nil
}

func (f *fakeConverter) RevertPersonConversion(_ context.Context, rec PersonConversion) (string, error) {
	f.reverted = append(f.reverted, rec)
	return rec.Person.EntityID + "-restored", nil
}

func TestOrgNamedDecisions(t *testing.T) {
	ctx := context.Background()
	j := &Journal{Path: filepath.Join(t.TempDir(), "journal.jsonl")}
	a := lens.OrgNamedPerson{ID: lens.OrgNamedID("p-a"), PersonID: "p-a", Person: "Acme, Inc.", Reasons: []string{"x"}}
	b := lens.OrgNamedPerson{ID: lens.OrgNamedID("p-b"), PersonID: "p-b", Person: "Beta LLC", OrgID: "o-b"}

	if _, err := j.SubmitOrgNamed([]lens.OrgNamedPerson{{ID: "onp-x"}}); err == nil {
		t.Error("a proposal without a person was recorded")
	}
	added, err := j.SubmitOrgNamed([]lens.OrgNamedPerson{a, b})
	if err != nil || len(added) != 2 {
		t.Fatalf("added %v, %v", added, err)
	}
	if again, _ := j.SubmitOrgNamed([]lens.OrgNamedPerson{a}); len(again) != 0 {
		t.Error("a proposal was recorded twice")
	}
	if !IsOrgNamedProposal(a.ID) || IsOrgNamedProposal("pno-1") {
		t.Error("IsOrgNamedProposal misjudges the prefix")
	}

	w := &fakeConverter{fail: errors.New("boom")}
	if _, err := ApplyOrgNamed(ctx, w, j, a.ID, "jeff"); err == nil {
		t.Error("a failed conversion was applied")
	}
	w.fail = nil
	if _, err := ApplyOrgNamed(ctx, w, j, a.ID, ""); err == nil {
		t.Error("applied without a reviewer")
	}
	rec, err := ApplyOrgNamed(ctx, w, j, a.ID, "jeff")
	if err != nil || rec.OrgID != "org-p-a" || !rec.OrgCreated {
		t.Fatalf("apply = %+v, %v", rec, err)
	}
	if _, err := ApplyOrgNamed(ctx, w, j, a.ID, "jeff"); err == nil {
		t.Error("an applied proposal was applied again")
	}
	if err := RejectOrgNamed(j, a.ID, "jeff"); err == nil {
		t.Error("an applied proposal was rejected")
	}
	if _, err := RetractOrgNamed(ctx, w, j, b.ID, "jeff"); err == nil {
		t.Error("a pending proposal was retracted")
	}
	if err := RejectOrgNamed(j, b.ID, "jeff"); err != nil {
		t.Fatal(err)
	}

	entries, err := j.OrgNamedEntries()
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %+v, %v", entries, err)
	}
	text := FormatOrgNamedEntries(entries)
	for _, want := range []string{"APPLIED", "now organization [org-p-a]", "kept for undo", "REJECTED",
		`its contact record already names it [o-b]`} {
		if !strings.Contains(text, want) {
			t.Errorf("listing lacks %q:\n%s", want, text)
		}
	}

	restored, err := RetractOrgNamed(ctx, w, j, a.ID, "jeff")
	if err != nil || restored != "p-a-restored" || len(w.reverted) != 1 || w.reverted[0].OrgID != "org-p-a" {
		t.Fatalf("retract = %q, %v, %+v", restored, err, w.reverted)
	}
	state, err := j.OrgNamedState()
	if err != nil || state[a.ID].Status != ProposalRetracted || state[a.ID].Outcome.RestoredID != "p-a-restored" {
		t.Errorf("state = %+v, %v", state[a.ID], err)
	}
	if _, err := RetractOrgNamed(ctx, w, j, a.ID, "jeff"); err == nil {
		t.Error("a retracted proposal was retracted again")
	}
}
