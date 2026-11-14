// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// owaspCertificateFixture holds owasp.org with no documented owner and a
// certificate that lists it, issued by Let's Encrypt.
func owaspCertificateFixture() graphtest.VendorGraph {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{
		"owasp": {ID: "owasp", Type: "FQDN", Key: "owasp.org", Content: map[string]any{"name": "owasp.org"}},
		"cert": {ID: "cert", Type: "TLSCertificate", Key: "4566311",
			Content: map[string]any{"subject_common_name": "owasp.org"}},
		"issuer": {ID: "issuer", Type: "ContactRecord", Key: "https://crt.example/issuer"},
		"le":     {ID: "le", Type: "Organization", Key: "le", Content: map[string]any{"name": "let's encrypt"}},
	}, Links: []graph.Relation{
		{ID: "e1", FromID: "cert", ToID: "owasp", Label: "san_dns_name", Type: "SimpleRelation"},
		{ID: "e2", FromID: "cert", ToID: "issuer", Label: "issuer_contact", Type: "SimpleRelation"},
		{ID: "e3", FromID: "issuer", ToID: "le", Label: "organization", Type: "SimpleRelation"},
	}}

	return graphtest.VendorGraph{PlannedGraph: graphtest.PlannedGraph{FakeGraph: g}}
}

func campus() (graph.Graph, graph.SchemaCatalog) {
	return graphtest.VendorFixture(), graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
}

func campusDNS() (graph.Graph, graph.SchemaCatalog) {
	return graphtest.LargeFQDNInventoryFixture(), graphtest.FQDNInventoryCatalog
}

func owaspCerts() (graph.Graph, graph.SchemaCatalog) {
	return owaspCertificateFixture(), graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
}

// sunyitServicesFixture is a namespace whose names reach services directly
// (www over a port relation), through an IP address (mail), or not at all
// (vpn). It has no documented owner.
func sunyitServicesFixture() graphtest.VendorGraph {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	named := func(id, typ, name string) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: name, Content: map[string]any{"name": name}}
	}

	named("sunyit.edu", "FQDN", "sunyit.edu")
	for _, n := range []string{"www", "mail", "vpn"} {
		named(n+".sunyit.edu", "FQDN", n+".sunyit.edu")
		g.Links = append(g.Links, graph.Relation{ID: "node-" + n, FromID: "sunyit.edu", ToID: n + ".sunyit.edu",
			Label: "node", Type: "SimpleRelation"})
	}

	g.Assets["ip-mail"] = graph.Asset{ID: "ip-mail", Type: "IPAddress", Key: "192.0.2.25",
		Content: map[string]any{"address": "192.0.2.25"}}
	g.Assets["svc-https"] = graph.Asset{ID: "svc-https", Type: "Service", Key: "a1b2",
		Content: map[string]any{"unique_id": "a1b2", "service_type": "https"}}
	g.Assets["svc-smtp"] = graph.Asset{ID: "svc-smtp", Type: "Service", Key: "c3d4",
		Content: map[string]any{"unique_id": "c3d4", "service_type": "smtp"}}
	g.Links = append(g.Links,
		graph.Relation{ID: "p-www", FromID: "www.sunyit.edu", ToID: "svc-https", Label: "port", Type: "PortRelation",
			Content: map[string]any{"label": "port", "port_number": 443, "protocol": "tcp"}},
		graph.Relation{ID: "a-mail", FromID: "mail.sunyit.edu", ToID: "ip-mail", Label: "dns_record",
			Type: "BasicDNSRelation"},
		graph.Relation{ID: "p-mail", FromID: "ip-mail", ToID: "svc-smtp", Label: "port", Type: "PortRelation",
			Content: map[string]any{"label": "port", "port_number": 25, "protocol": "tcp"}})
	return graphtest.VendorGraph{PlannedGraph: graphtest.PlannedGraph{FakeGraph: g}}
}

func campusGaps() (graph.Graph, graph.SchemaCatalog) {
	return graphtest.CampusGapsFixture(), graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
}

func sunyitServices() (graph.Graph, graph.SchemaCatalog) {
	return sunyitServicesFixture(), graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
}

// campusTXT adds what colgate.edu's DNS TXT records show to the campus
// fixture: an SPF record naming Google Workspace and a sender no catalog
// entry knows, a verification token the DNS-SD plugin stored as a
// verified_for relationship to Google, and one it did not recognize.
func campusTXT() (graph.Graph, graph.SchemaCatalog) {
	g := graphtest.VendorFixture()
	g.Assets["google"] = graph.Asset{ID: "google", Type: "Organization", Key: "Google LLC",
		Content: map[string]any{"name": "Google LLC"}}
	g.Links = append(g.Links, graph.Relation{ID: "colgate.edu-verified_for-google", FromID: "colgate.edu",
		ToID: "google", Label: "verified_for", Type: "SimpleRelation"})
	txt := func(id, data string) graph.Evidence {
		return graph.Evidence{ID: id, SubjectID: "colgate.edu", Kind: "property", Property: map[string]any{
			"property_name": graph.DNSRecordProperty, "header": map[string]any{"rr_type": graph.RRTypeTXT}, "data": data}}
	}
	g.EvidenceByID = map[string][]graph.Evidence{"colgate.edu": {
		txt("t1", "v=spf1 include:_spf.google.com include:spf.acme-mailer.example -all"),
		txt("t2", "acme-domain-verification=1"),
	}}

	return g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
}

// institutionFamily is the Johns Hopkins shaped family fixture.
func institutionFamily() (graph.Graph, graph.SchemaCatalog) {
	return graphtest.VendorGraph{PlannedGraph: graphtest.PlannedGraph{FakeGraph: graphtest.FamilyGraph()}}, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
}

// corporateGroup is a GLEIF-shaped corporate group.
func corporateGroup() (graph.Graph, graph.SchemaCatalog) {
	return graphtest.GroupFixture(), graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
}

// campusServices adds probe-stored services to the campus vendor fixture.
func campusServices() (graph.Graph, graph.SchemaCatalog) {
	return graphtest.ServicesFixture(), graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
}

// collegeGroup puts two colleges under one parent.
func collegeGroup() (graph.Graph, graph.SchemaCatalog) {
	return graphtest.GroupVendorFixture(), graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
}

// evalFixtures are the graphs offline evaluation cases name.
var evalFixtures = map[string]func() (graph.Graph, graph.SchemaCatalog){
	"campus":             campus,
	"campus-web":         graphtest.CampusWeb,
	"campus-dns":         campusDNS,
	"owasp-certificate":  owaspCerts,
	"sunyit-services":    sunyitServices,
	"campus-gaps":        campusGaps,
	"campus-txt":         campusTXT,
	"institution-family": institutionFamily,
	"corporate-group":    corporateGroup,
	"campus-services":    campusServices,
	"college-group":      collegeGroup,
}

// Every reported question runs here on each CI build.
func TestQuestionEvaluationSet(t *testing.T) {
	cases, err := DefaultEvalCases()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("the evaluation set is empty")
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.Offline == nil {
				t.Skip("no offline fixture")
			}

			fixture, ok := evalFixtures[c.Offline.Fixture]
			if !ok {
				t.Fatalf("unknown fixture %q", c.Offline.Fixture)
			}

			g, catalog := fixture()
			replies := c.Offline.PlannerReplies
			if len(replies) == 0 {
				replies = []string{`{"error":"this case must not call the model"}`}
			}

			agent := Agent{Model: &plannerModel{replies: replies},
				Runner: ToolRunner{Graph: g, Catalog: catalog, Limits: graph.DefaultLimits()}}
			res := agent.RunEvalCase(context.Background(), c, c.Offline.Checks,
				AdaptiveOptions{MaxInventory: lens.DefaultInventoryNames})
			if !res.Pass {
				t.Fatalf("%s\n%s\nanswer:\n%s", c.Question, strings.Join(res.Failures, "\n"), res.Text)
			}
		})
	}
}

func TestLoadEvalCasesRejectsBadSets(t *testing.T) {
	for _, doc := range []string{
		`{"cases":[{"id":"","question":"q"}]}`,
		`{"cases":[{"id":"a","question":"q"},{"id":"a","question":"r"}]}`,
		`{"cases":[{"id":"a","question":"q","expect":{"answer":"guess"}}]}`,
		`{"cases":[{"id":"a","question":"q","unknown":true}]}`,
	} {
		if _, err := LoadEvalCases([]byte(doc)); err == nil {
			t.Errorf("accepted invalid evaluation set %s", doc)
		}
	}
}

func TestEvalFailuresAreReported(t *testing.T) {
	agent := Agent{Model: &plannerModel{replies: []string{"{}"}},
		Runner: ToolRunner{Graph: graphtest.VendorFixture(), Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, Limits: graph.DefaultLimits()}}
	zero := 0
	c := EvalCase{ID: "x", Question: "Which third-party vendors are used by colgate.edu?",
		Expect: EvalExpect{Answer: lens.LensControlled, MaxModelCalls: &zero}}

	res := agent.RunEvalCase(context.Background(), c, EvalChecks{ResultsInclude: []string{"nobody"}}, AdaptiveOptions{})
	if res.Pass || len(res.Failures) != 2 {
		t.Fatalf("want two failures (answer kind, missing result), got %v", res.Failures)
	}

	text := FormatEvalResults([]EvalResult{res})
	if !strings.Contains(text, "0 of 1 passed") {
		t.Error("summary line missing")
	}
	if !strings.Contains(text, "plan: List the third-party vendors used by the assets FQDN") {
		t.Errorf("failed case does not show its plan:\n%s", text)
	}
}

func TestEvalResultsShowRejectedPlans(t *testing.T) {
	cases, err := DefaultEvalCases()
	if err != nil {
		t.Fatal(err)
	}

	var c EvalCase
	for _, ec := range cases {
		if ec.ID == "colgate-website-hosting-table" {
			c = ec
		}
	}
	if c.Offline == nil {
		t.Fatal("colgate-website-hosting-table has no offline fixture")
	}

	// Two unparseable plans are rejected and the recorded reply is accepted:
	// three calls, over the case's budget of two.
	bad := "a table of websites"
	g, catalog := evalFixtures[c.Offline.Fixture]()
	agent := Agent{Model: &plannerModel{replies: []string{bad, bad, c.Offline.PlannerReplies[0]}},
		Runner: ToolRunner{Graph: g, Catalog: catalog, Limits: graph.DefaultLimits()}}
	res := agent.RunEvalCase(context.Background(), c, c.Offline.Checks, AdaptiveOptions{MaxInventory: lens.DefaultInventoryNames})
	if res.Pass || len(res.Corrections) != 2 || res.ModelCalls != 3 {
		t.Fatalf("result = %+v", res)
	}

	text := FormatEvalResults([]EvalResult{res})
	if !strings.Contains(text, "rejected plan 1: ") || !strings.Contains(text, "rejected plan 2: ") {
		t.Errorf("output lacks the rejected plan:\n%s", text)
	}
}

func TestTableRowTypeRepairedWithoutACall(t *testing.T) {
	cases, err := DefaultEvalCases()
	if err != nil {
		t.Fatal(err)
	}

	var c EvalCase
	for _, ec := range cases {
		if ec.ID == "colgate-website-hosting-table" {
			c = ec
		}
	}

	// The controller as the row type, as Qwen chose live: the rows become the
	// first ownable type the question names (website: URL), with no retry.
	bad := strings.Replace(c.Offline.PlannerReplies[0], `"target_types":["URL"]`, `"target_types":["Organization"]`, 1)
	g, catalog := evalFixtures[c.Offline.Fixture]()
	agent := Agent{Model: &plannerModel{replies: []string{bad}},
		Runner: ToolRunner{Graph: g, Catalog: catalog, Limits: graph.DefaultLimits()}}
	res := agent.RunEvalCase(context.Background(), c, c.Offline.Checks, AdaptiveOptions{MaxInventory: lens.DefaultInventoryNames})
	if !res.Pass || res.ModelCalls != 1 || len(res.Corrections) != 0 {
		t.Fatalf("result = %+v", res)
	}
}

func TestMentionedTypesInOrder(t *testing.T) {
	_, catalog := evalFixtures["campus-web"]()
	got := mentionedTypesInOrder("a table with each website, its IP address and hosting provider", catalog)
	if len(got) < 2 || got[0] != "URL" || got[1] != "IPAddress" {
		t.Errorf("types = %v", got)
	}
}
