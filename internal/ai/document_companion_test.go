// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// companionStore is a runStore that also answers edge queries and deletes.
type companionStore struct{ runStore }

func (s *companionStore) IncomingEdges(context.Context, *dbt.Entity, time.Time, ...string) ([]*dbt.Edge, error) {
	return nil, nil
}

func (s *companionStore) OutgoingEdges(context.Context, *dbt.Entity, time.Time, ...string) ([]*dbt.Edge, error) {
	return nil, nil
}

func (s *companionStore) DeleteEntity(context.Context, string) error { return nil }

func (s *companionStore) FindEntityTags(context.Context, *dbt.Entity, time.Time, ...string) ([]*dbt.EntityTag, error) {
	return nil, nil
}

func (s *companionStore) CreateEdgeProperty(context.Context, *dbt.Edge, oam.Property) (*dbt.EdgeTag, error) {
	return &dbt.EdgeTag{ID: "et"}, nil
}

func (s *companionStore) DeleteEdgeTag(context.Context, string) error { return nil }

// companionActivity records what a companion submits and counts.
type companionActivity struct {
	mu        sync.Mutex
	submitted []string
	counts    map[string]int
}

func (a *companionActivity) activity() collect.Activity {
	return collect.Activity{
		Submit: func(_ context.Context, asset oam.Asset) (string, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.submitted = append(a.submitted, string(asset.AssetType())+":"+asset.Key())
			return "lead-" + asset.Key(), nil
		},
		Count: func(name string, n int) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.counts[name] += n
		},
	}
}

// During a run the companion fetches the target's documents, reads all of
// their text, stores the findings and hands the run's session every asset
// they name that the engine collects from and the database lacks, within the
// run's lead budget; an asset the database holds is never a lead, and an
// organization the document ties to no anchor is not one either.
func TestDocumentCompanionSubmitsLeads(t *testing.T) {
	g := documentFixture()
	reply := `{"category": "annual_report", "assets": [
	  {"type": "FQDN", "value": "vpn.sunyit.edu", "quote": "Staff connect remotely through vpn.sunyit.edu"},
	  {"type": "Netblock", "value": "192.0.2.0/24", "quote": "the data center hosts 192.0.2.0/24"},
	  {"type": "Product", "value": "Workday", "quote": "The college uses Workday for payroll."}],
	 "statements": [
	  {"subject": "SUNY Poly Foundation", "subject_type": "Organization", "predicate": "unit_of",
	   "object": "SUNY Polytechnic Institute", "object_type": "Organization",
	   "quote": "The SUNY Poly Foundation is a division of SUNY Polytechnic Institute."}],
	 "attributes": []}`
	store := &companionStore{runStore{props: map[string]oam.Property{}}}
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	fetcher := &textFetcher{texts: map[string]string{"https://www.owasp.org/a.pdf": docText}}
	c := &DocumentCompanion{Graph: g, Store: store, Journal: j, Model: &docModel{replies: []string{reply}},
		ModelID: "test-model", Interval: time.Hour, MaxLeads: 3, Fetcher: fetcher,
		Schema: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}}
	run := collect.Run{ID: "run1", Plan: collect.Plan{ScopeType: "domain", ScopeValue: "owasp.org"}}
	act := &companionActivity{counts: map[string]int{}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pending := c.Begin(ctx, run, act.activity())
	if pending == nil {
		t.Fatal("no pending report")
	}
	// the engine is done: the companion reads what remains before the run ends
	if !pending() {
		t.Fatal("not pending before a pass after the engine finished")
	}
	deadline := time.Now().Add(5 * time.Second)
	for pending() {
		if time.Now().After(deadline) {
			t.Fatal("the companion never finished its pass")
		}
		time.Sleep(5 * time.Millisecond)
	}

	act.mu.Lock()
	defer act.mu.Unlock()
	got := append([]string(nil), act.submitted...)
	sort.Strings(got)
	// a host and a range are leads; the organizations, named only in relation
	// to each other, are findings only, and the product is no lead
	want := []string{"FQDN:vpn.sunyit.edu", "Netblock:192.0.2.0/24"}
	if len(got) != len(want) {
		t.Fatalf("submitted %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("submitted %v, want %v", got, want)
		}
	}
	if act.counts[ActivityDocumentsRead] != 1 || act.counts[ActivityLeads] != 2 ||
		act.counts[ActivityLeadsWaiting] != 0 {
		t.Fatalf("counts %v", act.counts)
	}

	leads, err := j.DocumentLeads()
	if err != nil || len(leads) != 2 {
		t.Fatalf("journaled leads %+v, %v", leads, err)
	}
	for _, l := range leads {
		if !review.IsDocumentLead(l.ID) || l.RunID != "run1" || l.Type == "" {
			t.Errorf("lead %+v", l)
		}
	}

	// the engine confirmed none of them when the run ended: all expire
	c.Finish(context.Background(), run)
	leads, _ = j.DocumentLeads()
	for _, l := range leads {
		if l.Status != review.ProposalRetracted || l.Reviewer != review.DocumentLeadExpiredReviewer {
			t.Errorf("unconfirmed lead not expired: %+v", l)
		}
	}
}

// Every collectable type a document can name has a lead; people and products
// do not, and a malformed value gives none.
func TestLeadFor(t *testing.T) {
	for _, tc := range []struct {
		typ, value, key string
	}{
		{"FQDN", "VPN.Example.edu.", "vpn.example.edu"},
		{"IPAddress", "192.0.2.10", "192.0.2.10"},
		{"Netblock", "192.0.2.7/24", "192.0.2.0/24"},
		{"AutonomousSystem", "AS64496", "64496"},
		{"Identifier", "Jane.Doe@Example.edu", "email:jane.doe@example.edu"},
		{"URL", "https://portal.example.edu/login", "https://portal.example.edu/login"},
		{"Phone", "+1 315-555-0300", "+13155550300"},
		{"Phone", "(315) 792-5400", "+13157925400"},
		{"StreetAddress", "100 Seymour Rd, Utica, NY 13502", "100 Seymour Rd, Utica, NY 13502"},
		{"Organization", "SUNY Poly Foundation", "SUNY Poly Foundation"},
	} {
		l, ok := leadFor(tc.typ, tc.value, "US")
		if !ok || l.asset.Key() != tc.key || string(l.asset.AssetType()) != tc.typ {
			t.Errorf("leadFor(%s, %q) = %v %v, want key %q", tc.typ, tc.value, l.asset, ok, tc.key)
		}
	}
	for _, tc := range []struct{ typ, value string }{
		{"Person", "Jane Doe"}, {"Product", "Workday"}, {"FQDN", "not a host"}, {"Phone", "555-0100"},
		{"Identifier", "LEI 5493001KJTIIGC8Y1R12"}, {"Organization", "third parties"},
		{"Organization", "Office of Events"}, {"Organization", "Department of Computer Science"},
		{"Organization", "Counseling"}, {"Organization", "Rapid Response"}, {"Organization", "Health Center"},
		{"URL", "https://www.owasp.org/about/?subject='To"}, {"URL", "mailto:help@owasp.org"},
	} {
		if _, ok := leadFor(tc.typ, tc.value, "US"); ok {
			t.Errorf("leadFor(%s, %q) gave a lead", tc.typ, tc.value)
		}
	}
}

// A negative lead budget stores findings but submits nothing.
func TestDocumentCompanionWithoutLeads(t *testing.T) {
	st := &companionRun{seen: map[string]bool{}}
	act := &companionActivity{counts: map[string]int{}}
	c := &DocumentCompanion{MaxLeads: -1}
	c.submitLeads(context.Background(), collect.Run{ID: "r"}, act.activity(), st, DocumentResult{
		Stored: []review.StoredStatement{{Kind: FindingAsset, Subject: "vpn.example.edu", SubjectType: "FQDN"}}})
	if len(act.submitted) != 0 {
		t.Fatalf("submitted %v with leads off", act.submitted)
	}
}

// A generic unit of the publisher is not a lead; a public body with a unit-like
// name, or a longer name, is.
func TestGenericUnit(t *testing.T) {
	for name, want := range map[string]bool{
		"Office of Events":                       true,
		"Department of Computer Science":         true,
		"Center for Teaching":                    true,
		"U.S. Department of Education":           false,
		"New York State Office of Mental Health": false,
		"Sodexho":                                false,
		"Office of the Vice President for Academic Affairs and Provost": false,
	} {
		if got := genericUnit(name); got != want {
			t.Errorf("genericUnit(%q) = %v, want %v", name, got, want)
		}
	}
}

// An organization is a lead only when a finding of the same document relates
// it to an anchor; one related only to another organization, or named alone,
// is kept as a finding.
func TestAnchoredOrganizations(t *testing.T) {
	anchored := anchoredOrganizations([]review.StoredStatement{
		{Kind: FindingRelation, Subject: "Acme  Hosting Partners", SubjectType: "Organization",
			Predicate: "location", Object: "1 Main St, Utica, NY 13501", ObjectType: "StreetAddress"},
		{Kind: FindingRelation, Subject: "registrar.example.net", SubjectType: "FQDN",
			Predicate: "registrant", Object: "Example Registrar LLC", ObjectType: "Organization"},
		{Kind: FindingRelation, Subject: "SUNY Poly Foundation", SubjectType: "Organization",
			Predicate: "unit_of", Object: "SUNY Polytechnic Institute", ObjectType: "Organization"},
		{Kind: FindingAsset, Subject: "Sodexho", SubjectType: "Organization"},
		{Kind: FindingAttribute, Subject: "Sodexho", SubjectType: "Organization", Field: "industry",
			Detail: "Food service"},
	})
	for name, want := range map[string]bool{
		"Acme Hosting Partners":      true,
		"Example Registrar LLC":      true,
		"SUNY Poly Foundation":       false,
		"SUNY Polytechnic Institute": false,
		"Sodexho":                    false,
	} {
		l, ok := leadFor("Organization", name, "US")
		if !ok {
			t.Fatalf("leadFor(Organization, %q) gave no lead", name)
		}
		if got := anchoredLead(l, anchored); got != want {
			t.Errorf("anchoredLead(%q) = %v, want %v", name, got, want)
		}
	}
	if l, _ := leadFor("FQDN", "vpn.example.edu", "US"); !anchoredLead(l, anchored) {
		t.Error("a host was held back as unanchored")
	}
}

// An organization a document names alone is a finding, not a lead, and does
// not wait for the budget; it becomes a lead once a later document ties it to
// an anchor.
func TestDocumentCompanionOrganizationLeads(t *testing.T) {
	store := &companionStore{runStore{props: map[string]oam.Property{}}}
	c := &DocumentCompanion{Graph: documentFixture(), Store: store, MaxLeads: 5,
		Journal: &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}, ModelID: "test-model"}
	st := &companionRun{seen: map[string]bool{}}
	act := &companionActivity{counts: map[string]int{}}
	run := collect.Run{ID: "r"}

	c.submitLeads(context.Background(), run, act.activity(), st, DocumentResult{Stored: []review.StoredStatement{
		{Kind: FindingAsset, Subject: "Apex Catering Services", SubjectType: "Organization"},
		{Kind: FindingAsset, Subject: "Zenith Facilities Group", SubjectType: "Organization"}}})
	if len(act.submitted) != 0 || act.counts[ActivityLeadsWaiting] != 0 {
		t.Fatalf("submitted %v, counts %v: organizations named alone are not leads", act.submitted, act.counts)
	}

	c.submitLeads(context.Background(), run, act.activity(), st, DocumentResult{Stored: []review.StoredStatement{
		{Kind: FindingRelation, Subject: "Zenith Facilities Group", SubjectType: "Organization",
			Predicate: "website", Object: "https://zenithfacilities.example/", ObjectType: "URL"}}})
	got := append([]string(nil), act.submitted...)
	sort.Strings(got)
	want := []string{"Organization:Zenith Facilities Group", "URL:https://zenithfacilities.example/"}
	if len(got) != len(want) || act.counts[ActivityLeadsWaiting] != 0 {
		t.Fatalf("submitted %v, counts %v, want %v", got, act.counts, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("submitted %v, want %v", got, want)
		}
	}
}

// A stale document's findings are stored, but give the run no leads.
func TestDocumentCompanionStaleDocument(t *testing.T) {
	if !lens.StaleDocument(time.Now().AddDate(-15, 0, 0), time.Now()) || lens.StaleDocument(time.Time{}, time.Now()) ||
		lens.StaleDocument(time.Now().AddDate(-1, 0, 0), time.Now()) {
		t.Fatal("StaleDocument misjudges a 15-year-old, an undated or a recent document")
	}
}

// A run tries a document that cannot be read once, and one whose failure may
// pass twice, so documents that always fail do not fill every pass.
func TestCompanionSkipsFailedDocuments(t *testing.T) {
	st := &companionRun{failed: map[string]failedDocument{
		"extract": {kind: FailureExtract, attempts: 1},
		"busy":    {kind: FailureModelTimeout, attempts: 1},
		"down":    {kind: FailureFetch, attempts: 2},
	}}
	for id, want := range map[string]bool{"extract": true, "busy": false, "down": true, "new": false} {
		if got := st.skip(id); got != want {
			t.Errorf("skip(%q) = %v, want %v", id, got, want)
		}
	}
}

// The run is held for the documents left only while, at this run's reading
// pace, they could be read within the hold.
func TestCompanionHoldEndsWhenDocumentsOutlastIt(t *testing.T) {
	st := &companionRun{doneAt: time.Now().Add(-2 * time.Minute), remaining: 6,
		readTime: 10 * time.Minute, readDocs: 5}
	// 2 minutes held, 6 documents at 2 minutes each: 14 minutes in all
	if st.outlastsHold(15 * time.Minute) {
		t.Error("documents that fit within the hold ended it")
	}
	st.remaining = 7
	if !st.outlastsHold(15 * time.Minute) {
		t.Error("documents that outlast the hold kept the run open")
	}
	if st.outlastsHold(0) {
		t.Error("a companion without a hold estimated one")
	}

	unknown := &companionRun{doneAt: time.Now(), remaining: 100}
	if unknown.outlastsHold(time.Minute) {
		t.Error("the hold ended before any document set a pace")
	}
}

// The run's own target written as its domain label or acronym is not a lead;
// other organizations, and other kinds of lead, are.
func TestSelfReference(t *testing.T) {
	labels := targetLabels(collect.Run{Plan: collect.Plan{ScopeType: "domain", ScopeValue: "owasp.org"}})
	if !labels["owasp"] || len(labels) != 1 {
		t.Fatalf("labels %v", labels)
	}
	if uk := targetLabels(collect.Run{Plan: collect.Plan{ScopeType: "domain", ScopeValue: "www.acme.co.uk"}}); !uk["acme"] {
		t.Errorf("labels for acme.co.uk %v", uk)
	}
	for name, want := range map[string]bool{"OWASP": true, "O.W.A.S.P.": true, "Example Police Department": false,
		"OWASP Foundation": false} {
		l, ok := leadFor("Organization", name, "US")
		if !ok {
			t.Fatalf("leadFor(Organization, %q) gave no lead", name)
		}
		if got := selfReference(l, labels); got != want {
			t.Errorf("selfReference(%q) = %v, want %v", name, got, want)
		}
	}
	if l, _ := leadFor("FQDN", "owasp.org", "US"); selfReference(l, labels) {
		t.Error("a host was treated as the target's own name")
	}
}
