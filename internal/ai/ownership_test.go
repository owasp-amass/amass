// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// testAttribution mirrors the reviewed entries of oam_relations.yaml that
// these tests traverse.
type testAttribution map[string]string

func (t testAttribution) Attribution(src, label, rt, dst string) (string, bool) {
	v, ok := t[src+"|"+label+"|"+rt+"|"+dst]
	return v, ok
}

var reviewedAttribution = testAttribution{
	"TLSCertificate|san_dns_name|SimpleRelation|FQDN":              "shared",
	"TLSCertificate|common_name|SimpleRelation|FQDN":               "same_subject",
	"TLSCertificate|issuer_contact|SimpleRelation|ContactRecord":   "third_party",
	"TLSCertificate|subject_contact|SimpleRelation|ContactRecord":  "controller",
	"ContactRecord|organization|SimpleRelation|Organization":       "same_subject",
	"FQDN|registration|SimpleRelation|DomainRecord":                "same_subject",
	"DomainRecord|registrant_contact|SimpleRelation|ContactRecord": "controller",
	"DomainRecord|registrar_contact|SimpleRelation|ContactRecord":  "third_party",
	"Organization|subsidiary|SimpleRelation|Organization":          "controls",
	"Organization|website|SimpleRelation|URL":                      "controls",
	"URL|domain|SimpleRelation|FQDN":                               "same_subject",
	"FQDN|dns_record|BasicDNSRelation|IPAddress":                   "infrastructure",
	"Netblock|contains|SimpleRelation|IPAddress":                   "same_subject",
}

// The Docker Desktop run that motivated this: owasp.org reached Let's
// Encrypt through a certificate SAN and the certificate's issuer.
func issuerPath() graph.PlanMatch {
	return graph.PlanMatch{PathID: "p-issuer",
		Nodes: []graph.Asset{graphtest.Asset("fqdn", "FQDN", "owasp.org"), graphtest.Asset("cert", "TLSCertificate", "4566311"),
			graphtest.Asset("issuer", "ContactRecord", "Issuer"), graphtest.Asset("le", "Organization", "let's encrypt")},
		Edges: []graph.Relation{graphtest.Edge("e1", "cert", "fqdn", "san_dns_name"), graphtest.Edge("e2", "cert", "issuer", "issuer_contact"),
			graphtest.Edge("e3", "issuer", "le", "organization")}}
}

// owasp.org -> registration -> DomainRecord -> registrant -> contact -> OWASP
// Foundation, whose parent is a holding organization.
func registrantPath() graph.PlanMatch {
	return graph.PlanMatch{PathID: "p-owner",
		Nodes: []graph.Asset{graphtest.Asset("fqdn", "FQDN", "owasp.org"), graphtest.Asset("dr", "DomainRecord", "owasp.org"),
			graphtest.Asset("reg", "ContactRecord", "Registrant"), graphtest.Asset("owasp", "Organization", "OWASP Foundation"),
			graphtest.Asset("parent", "Organization", "Example Holdings")},
		Edges: []graph.Relation{graphtest.Edge("e4", "fqdn", "dr", "registration"), graphtest.Edge("e5", "dr", "reg", "registrant_contact"),
			graphtest.Edge("e6", "reg", "owasp", "organization"), graphtest.Edge("e7", "parent", "owasp", "subsidiary")}}
}

func TestOwnerAttributionStepRules(t *testing.T) {
	cases := map[string]struct {
		path graph.PlanMatch
		want bool
	}{
		"issuer is not an owner":  {issuerPath(), false},
		"registrant is the owner": {registrantPath(), true},
		"certificate subject is the owner": {graph.PlanMatch{
			Nodes: []graph.Asset{graphtest.Asset("f", "FQDN", "a.example"), graphtest.Asset("c", "TLSCertificate", "1"), graphtest.Asset("s",
				"ContactRecord", "Subject"), graphtest.Asset("o", "Organization", "Acme")},
			Edges: []graph.Relation{graphtest.Edge("1", "c", "f", "common_name"), graphtest.Edge("2", "c", "s",
				"subject_contact"), graphtest.Edge("3", "s", "o", "organization")}}, true},
		"organization website, traversed backward": {graph.PlanMatch{
			Nodes: []graph.Asset{graphtest.Asset("f", "FQDN", "a.example"), graphtest.Asset("u", "URL",
				"https://a.example/"), graphtest.Asset("o", "Organization", "Acme")},
			Edges: []graph.Relation{graphtest.Edge("1", "u", "f", "domain"), graphtest.Edge("2", "o", "u", "website")}}, true},
		"controller followed backward does not attribute": {graph.PlanMatch{
			Nodes: []graph.Asset{graphtest.Asset("o", "Organization", "Acme"), graphtest.Asset("s", "ContactRecord",
				"Subject"), graphtest.Asset("c", "TLSCertificate", "1"), graphtest.Asset("x", "Organization", "Other")},
			Edges: []graph.Relation{graphtest.Edge("1", "s", "o", "organization"), graphtest.Edge("2", "c", "s",
				"subject_contact"), graphtest.Edge("3", "c", "x", "issuer_contact")}}, false},
		"unknown relationship never attributes": {graph.PlanMatch{
			Nodes: []graph.Asset{graphtest.Asset("f", "FQDN", "a.example"), graphtest.Asset("o", "Organization", "Acme")},
			Edges: []graph.Relation{graphtest.Edge("1", "f", "o", "verified_for")}}, false},
	}
	for name, tc := range cases {
		if got, _, _ := ownerAttributed(reviewedAttribution, tc.path); got != tc.want {
			t.Errorf("%s: owner attributed = %v, want %v", name, got, tc.want)
		}
	}
}

func TestUltimateParentExcludesThirdPartiesAndReportsThem(t *testing.T) {
	goal := InvestigationGoal{Subject: PlanSubject{Type: "FQDN", Field: "name", Value: "owasp.org"},
		TargetTypes: []string{"Organization"}, Direction: "both", Purpose: "ultimate_parent"}
	paths := []graph.PlanMatch{issuerPath()}

	// Without semantics the old behaviour named the issuer as the parent.
	if got := eligibleAdaptivePaths(goal, paths); len(got) != 1 {
		t.Fatalf("baseline changed: %d paths", len(got))
	}
	if got := eligibleAdaptivePathsWith(goal, paths, reviewedAttribution); len(got) != 0 {
		t.Fatalf("a certificate issuer must not be a parent candidate: %+v", got)
	}

	conns := thirdPartyConnections(reviewedAttribution, paths)
	if len(conns) != 1 || conns[0].AssetID != "le" || conns[0].Via != "TLSCertificate issuer_contact" {
		t.Fatalf("third party not reported: %+v", conns)
	}
	if s := thirdPartySummary(conns); !strings.Contains(s,
		"let's encrypt (asset le) via TLSCertificate issuer_contact") {
		t.Fatalf("summary: %s", s)
	}

	// With a documented registrant, its parent is the answer and the issuer
	// is still reported separately.
	paths = append(paths, registrantPath())
	got := eligibleAdaptivePathsWith(goal, paths, reviewedAttribution)
	if len(got) != 1 || got[0].Nodes[len(got[0].Nodes)-1].ID != "parent" {
		t.Fatalf("expected the registrant's parent: %+v", got)
	}
	if conns := thirdPartyConnections(reviewedAttribution, paths); len(conns) != 1 || conns[0].AssetID != "le" {
		t.Fatalf("owner must not be listed as a third party: %+v", conns)
	}
}
