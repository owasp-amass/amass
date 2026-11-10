// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"
)

// oamAttribution is every entry of semantics/oam_relations.yaml, so the lens
// is tested against the reviewed table rather than a hand-picked subset.
var oamAttribution = testAttribution{
	"Account|id|SimpleRelation|Identifier":                             "attribute",
	"Account|user|SimpleRelation|Organization":                         "controller",
	"Account|user|SimpleRelation|Person":                               "controller",
	"AutnumRecord|abuse_contact|SimpleRelation|ContactRecord":          "third_party",
	"AutnumRecord|admin_contact|SimpleRelation|ContactRecord":          "controller",
	"AutnumRecord|rdap_url|SimpleRelation|URL":                         "third_party",
	"AutnumRecord|registrant|SimpleRelation|ContactRecord":             "controller",
	"AutnumRecord|technical_contact|SimpleRelation|ContactRecord":      "third_party",
	"AutnumRecord|whois_server|SimpleRelation|FQDN":                    "third_party",
	"AutonomousSystem|announces|SimpleRelation|Netblock":               "infrastructure",
	"AutonomousSystem|registration|SimpleRelation|AutnumRecord":        "same_subject",
	"ContactRecord|fqdn|SimpleRelation|FQDN":                           "attribute",
	"ContactRecord|id|SimpleRelation|Identifier":                       "attribute",
	"ContactRecord|location|SimpleRelation|Location":                   "attribute",
	"ContactRecord|organization|SimpleRelation|Organization":           "same_subject",
	"ContactRecord|person|SimpleRelation|Person":                       "same_subject",
	"ContactRecord|phone|SimpleRelation|Phone":                         "attribute",
	"ContactRecord|url|SimpleRelation|URL":                             "attribute",
	"DomainRecord|admin_contact|SimpleRelation|ContactRecord":          "controller",
	"DomainRecord|billing_contact|SimpleRelation|ContactRecord":        "controller",
	"DomainRecord|name_server|SimpleRelation|FQDN":                     "third_party",
	"DomainRecord|registrant_contact|SimpleRelation|ContactRecord":     "controller",
	"DomainRecord|registrar_contact|SimpleRelation|ContactRecord":      "third_party",
	"DomainRecord|technical_contact|SimpleRelation|ContactRecord":      "third_party",
	"DomainRecord|whois_server|SimpleRelation|FQDN":                    "third_party",
	"FQDN|dns_record|BasicDNSRelation|FQDN":                            "infrastructure",
	"FQDN|dns_record|BasicDNSRelation|IPAddress":                       "infrastructure",
	"FQDN|dns_record|PrefDNSRelation|FQDN":                             "infrastructure",
	"FQDN|dns_record|SRVDNSRelation|FQDN":                              "infrastructure",
	"FQDN|node|SimpleRelation|FQDN":                                    "same_subject",
	"FQDN|port|PortRelation|Service":                                   "infrastructure",
	"FQDN|registration|SimpleRelation|DomainRecord":                    "same_subject",
	"FQDN|verified_for|SimpleRelation|Organization":                    "third_party",
	"FQDN|verified_for|SimpleRelation|Service":                         "third_party",
	"File|contains|SimpleRelation|ContactRecord":                       "attribute",
	"File|contains|SimpleRelation|URL":                                 "attribute",
	"File|url|SimpleRelation|URL":                                      "attribute",
	"FundsTransfer|id|SimpleRelation|Identifier":                       "attribute",
	"FundsTransfer|recipient|SimpleRelation|Account":                   "attribute",
	"FundsTransfer|sender|SimpleRelation|Account":                      "attribute",
	"FundsTransfer|third_party|SimpleRelation|Organization":            "third_party",
	"IPAddress|port|PortRelation|Service":                              "infrastructure",
	"IPAddress|ptr_record|SimpleRelation|FQDN":                         "infrastructure",
	"IPNetRecord|abuse_contact|SimpleRelation|ContactRecord":           "third_party",
	"IPNetRecord|admin_contact|SimpleRelation|ContactRecord":           "controller",
	"IPNetRecord|rdap_url|SimpleRelation|URL":                          "third_party",
	"IPNetRecord|registrant|SimpleRelation|ContactRecord":              "controller",
	"IPNetRecord|technical_contact|SimpleRelation|ContactRecord":       "third_party",
	"IPNetRecord|whois_server|SimpleRelation|FQDN":                     "third_party",
	"Identifier|issuing_agent|SimpleRelation|ContactRecord":            "third_party",
	"Identifier|issuing_authority|SimpleRelation|ContactRecord":        "third_party",
	"Identifier|registration_agency|SimpleRelation|ContactRecord":      "third_party",
	"Location|id|SimpleRelation|Identifier":                            "attribute",
	"Netblock|contains|SimpleRelation|IPAddress":                       "same_subject",
	"Netblock|registration|SimpleRelation|IPNetRecord":                 "same_subject",
	"Organization|account|SimpleRelation|Account":                      "controls",
	"Organization|funding_source|SimpleRelation|Organization":          "attribute",
	"Organization|funding_source|SimpleRelation|Person":                "attribute",
	"Organization|hq_address|SimpleRelation|Location":                  "attribute",
	"Organization|id|SimpleRelation|Identifier":                        "attribute",
	"Organization|legal_address|SimpleRelation|Location":               "attribute",
	"Organization|location|SimpleRelation|Location":                    "attribute",
	"Organization|member|SimpleRelation|Person":                        "attribute",
	"Organization|org_unit|SimpleRelation|Organization":                "controls",
	"Organization|social_media_profile|SimpleRelation|URL":             "controls",
	"Organization|subsidiary|SimpleRelation|Organization":              "controls",
	"Organization|website|SimpleRelation|URL":                          "controls",
	"Person|account|SimpleRelation|Account":                            "controls",
	"Person|address|SimpleRelation|Location":                           "attribute",
	"Person|id|SimpleRelation|Identifier":                              "attribute",
	"Person|phone|SimpleRelation|Phone":                                "attribute",
	"Phone|account|SimpleRelation|Account":                             "attribute",
	"Phone|contact|SimpleRelation|ContactRecord":                       "attribute",
	"ProductRelease|id|SimpleRelation|Identifier":                      "attribute",
	"ProductRelease|website|SimpleRelation|URL":                        "controls",
	"Product|id|SimpleRelation|Identifier":                             "attribute",
	"Product|manufacturer|SimpleRelation|Organization":                 "controller",
	"Product|release|SimpleRelation|ProductRelease":                    "controls",
	"Product|website|SimpleRelation|URL":                               "controls",
	"Service|certificate|SimpleRelation|TLSCertificate":                "same_subject",
	"Service|product_used|SimpleRelation|Product":                      "third_party",
	"Service|product_used|SimpleRelation|ProductRelease":               "third_party",
	"Service|provider|SimpleRelation|Organization":                     "third_party",
	"Service|terms_of_service|SimpleRelation|File":                     "attribute",
	"Service|terms_of_service|SimpleRelation|URL":                      "attribute",
	"TLSCertificate|common_name|SimpleRelation|FQDN":                   "same_subject",
	"TLSCertificate|issuer_contact|SimpleRelation|ContactRecord":       "third_party",
	"TLSCertificate|issuing_certificate_url|SimpleRelation|URL":        "third_party",
	"TLSCertificate|issuing_certificate|SimpleRelation|TLSCertificate": "third_party",
	"TLSCertificate|ocsp_server|SimpleRelation|URL":                    "third_party",
	"TLSCertificate|san_dns_name|SimpleRelation|FQDN":                  "shared",
	"TLSCertificate|san_email_address|SimpleRelation|Identifier":       "shared",
	"TLSCertificate|san_ip_address|SimpleRelation|IPAddress":           "shared",
	"TLSCertificate|san_url|SimpleRelation|URL":                        "shared",
	"TLSCertificate|subject_contact|SimpleRelation|ContactRecord":      "controller",
	"URL|domain|SimpleRelation|FQDN":                                   "same_subject",
	"URL|file|SimpleRelation|File":                                     "attribute",
	"URL|ip_address|SimpleRelation|IPAddress":                          "infrastructure",
	"URL|port|PortRelation|Service":                                    "infrastructure",
}

// vendorCatalog is the full OAM attribution table with selectors.
type vendorCatalog struct{ planCatalog }

func (vendorCatalog) Attribution(src, label, rt, dst string) (string, bool) {
	return oamAttribution.Attribution(src, label, rt, dst)
}

// Relations returns every transition in the attribution table.
func (vendorCatalog) Relations() []RelationshipSchema {
	out := make([]RelationshipSchema, 0, len(oamAttribution))
	for k := range oamAttribution {
		p := strings.Split(k, "|")
		out = append(out, RelationshipSchema{SourceType: p[0], Label: p[1], RelationType: p[2], DestinationType: p[3]})
	}

	return out
}

// vendorGraph resolves Colgate University and colgate.edu.
type vendorGraph struct{ plannedGraph }

func (g vendorGraph) ResolveOrganizations(_ context.Context, q OrganizationQuery, _ int) (OrganizationResolution, error) {
	result := OrganizationResolution{Query: q, Status: "not_found", Candidates: []OrganizationCandidate{}}
	if strings.EqualFold(q.Name, "Colgate University") {
		result.Status = "matched"
		result.Candidates = []OrganizationCandidate{{Asset: g.assets["colgate"]}}
	}

	return result, nil
}

// vendorFixture models a university: its registrant contact ties the
// organization to colgate.edu and its own netblock. Outside parties are a
// registrar, a DNS host, a mail provider (MX), a CDN network and a
// certificate authority. A person shared with another college's contact
// must not pull that college into the footprint.
func vendorFixture() vendorGraph {
	g := fakeGraph{assets: map[string]Asset{}}
	add := func(id, typ, key string, content map[string]any) {
		g.assets[id] = Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.links = append(g.links, Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}
	named := func(id, typ, name string) { add(id, typ, name, map[string]any{"name": name}) }

	named("colgate", "Organization", "Colgate University")
	named("educause", "Organization", "EDUCAUSE")
	named("digicert", "Organization", "DigiCert Inc")
	named("hamilton", "Organization", "Hamilton College")
	add("cr-colgate", "ContactRecord", "https://rdap.example/colgate", nil)
	add("cr-educause", "ContactRecord", "https://whois.educause.edu/registrar", nil)
	add("cr-digicert", "ContactRecord", "https://crt.example/issuer", nil)
	add("cr-hamilton", "ContactRecord", "https://rdap.example/hamilton", nil)
	add("person", "Person", "Shared Person", map[string]any{"full_name": "Shared Person"})
	add("dr", "DomainRecord", "colgate.edu", map[string]any{"domain": "colgate.edu"})
	add("dr-hamilton", "DomainRecord", "hamilton.edu", map[string]any{"domain": "hamilton.edu"})
	for _, n := range []string{"colgate.edu", "www.colgate.edu", "portal.colgate.edu", "ns1.colgate.edu",
		"pdns1.ultradns.net", "mx1.pphosted.com", "hamilton.edu", "www.hamilton.edu", "x.cloudflare.com"} {
		named(n, "FQDN", n)
	}

	add("nb-own", "Netblock", "149.43.0.0/16", map[string]any{"cidr": "149.43.0.0/16"})
	add("ipnet-own", "IPNetRecord", "149.43.0.0/16", map[string]any{"name": "COLGATE-UNIV"})
	add("ip-own", "IPAddress", "149.43.1.1", map[string]any{"address": "149.43.1.1"})
	add("nb-cdn", "Netblock", "151.101.0.0/16", map[string]any{"cidr": "151.101.0.0/16"})
	add("as-cdn", "AutonomousSystem", "54113", map[string]any{"number": 54113})
	add("autnum-cdn", "AutnumRecord", "AS54113", map[string]any{"handle": "AS54113", "name": "FASTLY"})
	add("ip-cdn", "IPAddress", "151.101.1.1", map[string]any{"address": "151.101.1.1"})
	add("cert", "TLSCertificate", "1234", map[string]any{"serial_number": "1234"})
	add("as-own", "AutonomousSystem", "1289", map[string]any{"number": 1289})
	add("autnum-own", "AutnumRecord", "AS1289", map[string]any{"handle": "AS1289", "name": "COLGATE-UNIVERSITY"})

	link("cr-colgate", "organization", "colgate", "SimpleRelation")
	link("cr-colgate", "person", "person", "SimpleRelation")
	link("dr", "registrant_contact", "cr-colgate", "SimpleRelation")
	link("dr", "registrar_contact", "cr-educause", "SimpleRelation")
	link("cr-educause", "organization", "educause", "SimpleRelation")
	link("dr", "name_server", "ns1.colgate.edu", "SimpleRelation")
	link("dr", "name_server", "pdns1.ultradns.net", "SimpleRelation")
	link("colgate.edu", "registration", "dr", "SimpleRelation")
	link("colgate.edu", "node", "www.colgate.edu", "SimpleRelation")
	link("colgate.edu", "node", "portal.colgate.edu", "SimpleRelation")
	link("colgate.edu", "dns_record", "mx1.pphosted.com", "PrefDNSRelation")
	link("www.colgate.edu", "dns_record", "ip-cdn", "BasicDNSRelation")
	link("portal.colgate.edu", "dns_record", "ip-own", "BasicDNSRelation")
	link("nb-own", "registration", "ipnet-own", "SimpleRelation")
	link("ipnet-own", "registrant", "cr-colgate", "SimpleRelation")
	link("nb-own", "contains", "ip-own", "SimpleRelation")
	link("nb-cdn", "contains", "ip-cdn", "SimpleRelation")
	link("as-own", "announces", "nb-own", "SimpleRelation")
	link("as-own", "registration", "autnum-own", "SimpleRelation")
	link("autnum-own", "registrant", "cr-colgate", "SimpleRelation")
	link("as-cdn", "announces", "nb-cdn", "SimpleRelation")
	link("as-cdn", "registration", "autnum-cdn", "SimpleRelation")
	link("cert", "san_dns_name", "www.colgate.edu", "SimpleRelation")
	link("cert", "issuer_contact", "cr-digicert", "SimpleRelation")
	link("cr-digicert", "organization", "digicert", "SimpleRelation")

	// Hamilton College shares a person with Colgate's contact and uses its
	// own CDN; none of it belongs to Colgate.
	link("cr-hamilton", "organization", "hamilton", "SimpleRelation")
	link("cr-hamilton", "person", "person", "SimpleRelation")
	link("dr-hamilton", "registrant_contact", "cr-hamilton", "SimpleRelation")
	link("hamilton.edu", "registration", "dr-hamilton", "SimpleRelation")
	link("hamilton.edu", "node", "www.hamilton.edu", "SimpleRelation")
	link("www.hamilton.edu", "dns_record", "x.cloudflare.com", "BasicDNSRelation")

	return vendorGraph{plannedGraph{fakeGraph: g}}
}

func vendorAgent(model Model) Agent {
	return Agent{Model: model, Runner: ToolRunner{Graph: vendorFixture(), Catalog: vendorCatalog{testOAMCatalog},
		Limits: DefaultLimits()}}
}

func vendorNames(r *ThirdPartyReport) map[string]string {
	out := map[string]string{}
	for _, v := range r.Vendors {
		out[v.Vendor] = v.Kind
	}

	return out
}

func TestThirdPartyQuestionCompilesWithoutModel(t *testing.T) {
	for question, want := range map[string]PlanSubject{
		"Which third-party vendors are being used by the Colgate University organization?": {
			Type: "Organization", Name: "Colgate University"},
		"What vendors are used by Colgate University?":  {Type: "Organization", Name: "Colgate University"},
		"List the third-party providers of colgate.edu": {Type: "FQDN", Field: "name", Value: "colgate.edu"},
		"Which suppliers are relied upon by Colgate University's": {
			Type: "Organization", Name: "Colgate University"},
	} {
		q, ok := deterministicThirdPartyQuery(question)
		if !ok || q.Lens != LensThirdParty || q.Subject != want {
			t.Errorf("%q compiled to %+v (ok=%v), want subject %+v", question, q, ok, want)
		}
	}
}

func TestThirdPartyLensFindsVendorsOfOrganization(t *testing.T) {
	model := &plannerModel{}
	result, err := vendorAgent(model).AskAdaptive(context.Background(),
		"Which third-party vendors are being used by the Colgate University organization?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 0 {
		t.Fatalf("the third-party lens called the model %d time(s)", model.calls)
	}
	if result.ThirdPartyReport == nil || result.Incomplete {
		t.Fatalf("missing or partial report: %+v", result)
	}

	got := vendorNames(result.ThirdPartyReport)
	want := map[string]string{
		"AS54113 FASTLY": "Hosting and network providers",
		"ultradns.net":   "DNS hosting",
		"pphosted.com":   "DNS record targets (CNAME, NS, MX)",
		"EDUCAUSE":       "Domain registrars",
		"DigiCert Inc":   "Certificate authorities",
	}
	for name, kind := range want {
		if got[name] != kind {
			t.Errorf("vendor %s: kind %q, want %q (all: %v)", name, got[name], kind, got)
		}
	}
	for _, own := range []string{"Colgate University", "colgate.edu", "Hamilton College", "cloudflare.com"} {
		if _, ok := got[own]; ok {
			t.Errorf("%s reported as a vendor of Colgate University", own)
		}
	}
	if len(got) != len(want) {
		t.Errorf("vendors = %v, want exactly %v", got, want)
	}
	if !strings.Contains(result.Answer, "Certificate authorities:\n  DigiCert Inc: 1 asset(s)") {
		t.Errorf("answer does not group vendors by kind:\n%s", result.Answer)
	}
}

func TestThirdPartyLensFromDomainIncludesRegistrantNetworks(t *testing.T) {
	result, err := vendorAgent(nil).AskQuery(context.Background(),
		thirdPartyQuery("", PlanSubject{Type: "FQDN", Field: "name", Value: "colgate.edu"}, SourceCaller),
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	r := result.ThirdPartyReport
	if r == nil || len(r.Owners) != 1 || r.Owners[0] != "Colgate University" {
		t.Fatalf("domain lens did not find the registrant organization: %+v", r)
	}
	if r.FootprintTypes["Netblock"] != 1 || r.FootprintTypes["IPAddress"] != 1 {
		t.Errorf("registrant netblock missing from footprint: %v", r.FootprintTypes)
	}
	if _, ok := vendorNames(r)["AS54113 FASTLY"]; !ok {
		t.Errorf("CDN network missing: %v", vendorNames(r))
	}
}

func TestThirdPartyLensExplainsEmptyFootprint(t *testing.T) {
	g := vendorFixture()
	g.links = nil
	agent := Agent{Runner: ToolRunner{Graph: g, Catalog: vendorCatalog{testOAMCatalog}, Limits: DefaultLimits()}}

	result, err := agent.AskQuery(context.Background(),
		thirdPartyQuery("", PlanSubject{Type: "Organization", Name: "Colgate University"}, SourceCaller),
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Answer, "No assets are documented as controlled by Colgate University") {
		t.Fatalf("empty footprint not explained: %s", result.Answer)
	}
}

func TestModelVendorGoalIsPromotedToLens(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
			`"target_types":["Organization"],"direction":"both","purpose":"connected"}`,
	}}

	q, err := vendorAgent(model).CompileQuestion(context.Background(),
		"Tell me about the outside companies Colgate University relies on as vendors")
	if err != nil {
		t.Fatal(err)
	}
	if q.Lens != LensThirdParty || q.Subject.Name != "Colgate University" || q.Subject.Field != "" {
		t.Fatalf("model vendor goal was not promoted with organization resolution: %+v", q)
	}
}

func TestOrganizationSelectorUsesOrganizationResolution(t *testing.T) {
	got := organizationSubject(PlanSubject{Type: "Organization", Field: "name", Value: "Colgate University"})
	if !got.UsesOrganizationResolution() || got.Name != "Colgate University" {
		t.Fatalf("organizationSubject = %+v", got)
	}
}

func TestModelASNGoalIsPromotedToControlledLens(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
			`"target_types":["AutonomousSystem"],"direction":"both","purpose":"connected"}`,
	}}

	result, err := vendorAgent(model).AskAdaptive(context.Background(),
		"Which ASN is associated to the Colgate University organization?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 1 || result.Query == nil || result.Query.Lens != LensControlled {
		t.Fatalf("calls=%d query=%+v, want one planning call and the controlled lens", model.calls, result.Query)
	}

	r := result.ControlledReport
	if r == nil || len(r.Matches) != 1 {
		t.Fatalf("want exactly AS1289, got %+v", r)
	}

	last := r.Matches[0].Nodes[len(r.Matches[0].Nodes)-1]
	if last.ID != "as-own" || len(r.Matches[0].Edges) != 3 {
		t.Errorf("wrong ASN or path: %s", witnessChain(r.Matches[0]))
	}
	if r.FootprintTypes["FQDN"] != 0 || r.FootprintTypes["URL"] != 0 {
		t.Errorf("walk read assets that cannot lead to an ASN: %v", r.FootprintTypes)
	}
	if !strings.Contains(result.Answer, "Found 1 AutonomousSystem asset(s) controlled by Colgate University") ||
		!strings.Contains(result.Answer, "<--registration-- AutonomousSystem 1289") {
		t.Errorf("answer does not cite the witnessed path:\n%s", result.Answer)
	}
	if result.Diagram == "" {
		t.Error("controlled lens did not render a diagram")
	}
}

func TestControlledLensExcludesThirdPartyNetworks(t *testing.T) {
	q := Query{Version: QueryVersion, Subject: PlanSubject{Type: "Organization", Name: "Colgate University"},
		Traversal: TraversalExplore, TargetTypes: []string{"Netblock", "AutonomousSystem"}, Direction: "both",
		Purpose: "connected", Lens: LensControlled, Source: SourceCaller}

	result, err := vendorAgent(nil).AskQuery(context.Background(), q, AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, m := range result.ControlledReport.Matches {
		got[m.Nodes[len(m.Nodes)-1].ID] = true
	}
	if len(got) != 2 || !got["nb-own"] || !got["as-own"] {
		t.Fatalf("controlled networks = %v, want only nb-own and as-own (not the CDN)", got)
	}
}

func TestControlledPromotionRequiresAttributableTypes(t *testing.T) {
	cat := vendorCatalog{testOAMCatalog}
	for _, tc := range []struct {
		targets []string
		want    bool
	}{
		{[]string{"AutonomousSystem"}, true},
		{[]string{"Netblock", "FQDN"}, true},
		{[]string{"Organization"}, false},
		{[]string{"Phone"}, false},
		{nil, false},
	} {
		q := Query{Question: "Which assets does Colgate University have?", Purpose: "connected",
			Subject: PlanSubject{Type: "Organization", Name: "Colgate University"}, TargetTypes: tc.targets}
		if got := promoteControlledGoal(&q, cat, cat); got != tc.want {
			t.Errorf("targets %v: promoted=%v, want %v", tc.targets, got, tc.want)
		}
	}
}
