// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"
)

// owaspCertificateFixture holds owasp.org with no documented owner and a
// certificate that lists it, issued by Let's Encrypt.
func owaspCertificateFixture() vendorGraph {
	g := fakeGraph{assets: map[string]Asset{
		"owasp": {ID: "owasp", Type: "FQDN", Key: "owasp.org", Content: map[string]any{"name": "owasp.org"}},
		"cert": {ID: "cert", Type: "TLSCertificate", Key: "4566311",
			Content: map[string]any{"subject_common_name": "owasp.org"}},
		"issuer": {ID: "issuer", Type: "ContactRecord", Key: "https://crt.example/issuer"},
		"le":     {ID: "le", Type: "Organization", Key: "le", Content: map[string]any{"name": "let's encrypt"}},
	}, links: []Relation{
		{ID: "e1", FromID: "cert", ToID: "owasp", Label: "san_dns_name", Type: "SimpleRelation"},
		{ID: "e2", FromID: "cert", ToID: "issuer", Label: "issuer_contact", Type: "SimpleRelation"},
		{ID: "e3", FromID: "issuer", ToID: "le", Label: "organization", Type: "SimpleRelation"},
	}}

	return vendorGraph{plannedGraph{fakeGraph: g}}
}

// campusWebFixture adds websites to the campus: the organization's website
// on a CDN and a portal on its own network.
func campusWebFixture() vendorGraph {
	g := vendorFixture()
	g.assets["url-www"] = Asset{ID: "url-www", Type: "URL", Key: "https://www.colgate.edu",
		Content: map[string]any{"url": "https://www.colgate.edu"}}
	g.assets["url-portal"] = Asset{ID: "url-portal", Type: "URL", Key: "https://portal.colgate.edu",
		Content: map[string]any{"url": "https://portal.colgate.edu"}}
	g.links = append(g.links,
		Relation{ID: "w1", FromID: "colgate", ToID: "url-www", Label: "website", Type: "SimpleRelation"},
		Relation{ID: "w2", FromID: "url-www", ToID: "www.colgate.edu", Label: "domain", Type: "SimpleRelation"},
		Relation{ID: "w3", FromID: "url-portal", ToID: "portal.colgate.edu", Label: "domain", Type: "SimpleRelation"})
	return g
}

func campus() (Graph, SchemaCatalog) { return vendorFixture(), vendorCatalog{testOAMCatalog} }

func campusWeb() (Graph, SchemaCatalog) { return campusWebFixture(), vendorCatalog{testOAMCatalog} }

func campusDNS() (Graph, SchemaCatalog) { return largeFQDNInventoryFixture(), fqdnInventoryCatalog }

func owaspCerts() (Graph, SchemaCatalog) {
	return owaspCertificateFixture(), vendorCatalog{testOAMCatalog}
}

// sunyitServicesFixture is a namespace whose names reach services directly
// (www over a port relation), through an IP address (mail), or not at all
// (vpn). It has no documented owner.
func sunyitServicesFixture() vendorGraph {
	g := fakeGraph{assets: map[string]Asset{}}
	named := func(id, typ, name string) {
		g.assets[id] = Asset{ID: id, Type: typ, Key: name, Content: map[string]any{"name": name}}
	}

	named("sunyit.edu", "FQDN", "sunyit.edu")
	for _, n := range []string{"www", "mail", "vpn"} {
		named(n+".sunyit.edu", "FQDN", n+".sunyit.edu")
		g.links = append(g.links, Relation{ID: "node-" + n, FromID: "sunyit.edu", ToID: n + ".sunyit.edu",
			Label: "node", Type: "SimpleRelation"})
	}

	g.assets["ip-mail"] = Asset{ID: "ip-mail", Type: "IPAddress", Key: "192.0.2.25",
		Content: map[string]any{"address": "192.0.2.25"}}
	g.assets["svc-https"] = Asset{ID: "svc-https", Type: "Service", Key: "a1b2",
		Content: map[string]any{"unique_id": "a1b2", "service_type": "https"}}
	g.assets["svc-smtp"] = Asset{ID: "svc-smtp", Type: "Service", Key: "c3d4",
		Content: map[string]any{"unique_id": "c3d4", "service_type": "smtp"}}
	g.links = append(g.links,
		Relation{ID: "p-www", FromID: "www.sunyit.edu", ToID: "svc-https", Label: "port", Type: "PortRelation",
			Content: map[string]any{"label": "port", "port_number": 443, "protocol": "tcp"}},
		Relation{ID: "a-mail", FromID: "mail.sunyit.edu", ToID: "ip-mail", Label: "dns_record",
			Type: "BasicDNSRelation"},
		Relation{ID: "p-mail", FromID: "ip-mail", ToID: "svc-smtp", Label: "port", Type: "PortRelation",
			Content: map[string]any{"label": "port", "port_number": 25, "protocol": "tcp"}})
	return vendorGraph{plannedGraph{fakeGraph: g}}
}

func campusGaps() (Graph, SchemaCatalog) { return campusGapsFixture(), vendorCatalog{testOAMCatalog} }

func sunyitServices() (Graph, SchemaCatalog) {
	return sunyitServicesFixture(), vendorCatalog{testOAMCatalog}
}

// evalFixtures are the graphs offline evaluation cases name.
var evalFixtures = map[string]func() (Graph, SchemaCatalog){
	"campus":            campus,
	"campus-web":        campusWeb,
	"campus-dns":        campusDNS,
	"owasp-certificate": owaspCerts,
	"sunyit-services":   sunyitServices,
	"campus-gaps":       campusGaps,
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

			graph, catalog := fixture()
			replies := c.Offline.PlannerReplies
			if len(replies) == 0 {
				replies = []string{`{"error":"this case must not call the model"}`}
			}

			agent := Agent{Model: &plannerModel{replies: replies},
				Runner: ToolRunner{Graph: graph, Catalog: catalog, Limits: DefaultLimits()}}
			res := agent.RunEvalCase(context.Background(), c, c.Offline.Checks,
				AdaptiveOptions{MaxInventory: DefaultInventoryNames})
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
		Runner: ToolRunner{Graph: vendorFixture(), Catalog: vendorCatalog{testOAMCatalog}, Limits: DefaultLimits()}}
	zero := 0
	c := EvalCase{ID: "x", Question: "Which third-party vendors are used by colgate.edu?",
		Expect: EvalExpect{Answer: LensControlled, MaxModelCalls: &zero}}

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
