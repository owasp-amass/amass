// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// oamSemantics is every entry of semantics/oam_relations.yaml, so the
// lenses are tested against the reviewed table rather than a hand-picked
// subset. Regenerate it when the table changes.
var oamSemantics = map[string]RelationMeaning{
	"Account|id|SimpleRelation|Identifier":                             {"attribute", "identity", true},
	"Account|user|SimpleRelation|Organization":                         {"controller", "identity", true},
	"Account|user|SimpleRelation|Person":                               {"controller", "identity", true},
	"AutnumRecord|abuse_contact|SimpleRelation|ContactRecord":          {"third_party", "registration", false},
	"AutnumRecord|admin_contact|SimpleRelation|ContactRecord":          {"controller", "registration", true},
	"AutnumRecord|rdap_url|SimpleRelation|URL":                         {"third_party", "registration", false},
	"AutnumRecord|registrant|SimpleRelation|ContactRecord":             {"controller", "registration", true},
	"AutnumRecord|technical_contact|SimpleRelation|ContactRecord":      {"third_party", "registration", true},
	"AutnumRecord|whois_server|SimpleRelation|FQDN":                    {"third_party", "registration", false},
	"AutonomousSystem|announces|SimpleRelation|Netblock":               {"infrastructure", "network", true},
	"AutonomousSystem|registration|SimpleRelation|AutnumRecord":        {"same_subject", "registration", true},
	"ContactRecord|fqdn|SimpleRelation|FQDN":                           {"attribute", "contact", true},
	"ContactRecord|id|SimpleRelation|Identifier":                       {"attribute", "contact", true},
	"ContactRecord|location|SimpleRelation|Location":                   {"attribute", "contact", true},
	"ContactRecord|organization|SimpleRelation|Organization":           {"same_subject", "contact", true},
	"ContactRecord|person|SimpleRelation|Person":                       {"same_subject", "contact", true},
	"ContactRecord|phone|SimpleRelation|Phone":                         {"attribute", "contact", true},
	"ContactRecord|url|SimpleRelation|URL":                             {"attribute", "contact", true},
	"DomainRecord|admin_contact|SimpleRelation|ContactRecord":          {"controller", "registration", true},
	"DomainRecord|billing_contact|SimpleRelation|ContactRecord":        {"controller", "registration", true},
	"DomainRecord|name_server|SimpleRelation|FQDN":                     {"third_party", "dns", true},
	"DomainRecord|registrant_contact|SimpleRelation|ContactRecord":     {"controller", "registration", true},
	"DomainRecord|registrar_contact|SimpleRelation|ContactRecord":      {"third_party", "registration", true},
	"DomainRecord|technical_contact|SimpleRelation|ContactRecord":      {"third_party", "registration", true},
	"DomainRecord|whois_server|SimpleRelation|FQDN":                    {"third_party", "registration", false},
	"FQDN|dns_record|BasicDNSRelation|FQDN":                            {"infrastructure", "dns", true},
	"FQDN|dns_record|BasicDNSRelation|IPAddress":                       {"infrastructure", "dns", true},
	"FQDN|dns_record|PrefDNSRelation|FQDN":                             {"infrastructure", "dns", true},
	"FQDN|dns_record|SRVDNSRelation|FQDN":                              {"infrastructure", "dns", true},
	"FQDN|node|SimpleRelation|FQDN":                                    {"same_subject", "hierarchy", true},
	"FQDN|port|PortRelation|Service":                                   {"infrastructure", "network", true},
	"FQDN|registration|SimpleRelation|DomainRecord":                    {"same_subject", "registration", true},
	"FQDN|verified_for|SimpleRelation|Organization":                    {"third_party", "dns", true},
	"FQDN|verified_for|SimpleRelation|Service":                         {"third_party", "dns", true},
	"File|contains|SimpleRelation|ContactRecord":                       {"attribute", "web", true},
	"File|contains|SimpleRelation|URL":                                 {"attribute", "web", true},
	"File|url|SimpleRelation|URL":                                      {"attribute", "web", true},
	"FundsTransfer|id|SimpleRelation|Identifier":                       {"attribute", "financial", true},
	"FundsTransfer|recipient|SimpleRelation|Account":                   {"attribute", "financial", true},
	"FundsTransfer|sender|SimpleRelation|Account":                      {"attribute", "financial", true},
	"FundsTransfer|third_party|SimpleRelation|Organization":            {"third_party", "financial", true},
	"IPAddress|port|PortRelation|Service":                              {"infrastructure", "network", true},
	"IPAddress|ptr_record|SimpleRelation|FQDN":                         {"infrastructure", "dns", true},
	"IPNetRecord|abuse_contact|SimpleRelation|ContactRecord":           {"third_party", "registration", false},
	"IPNetRecord|admin_contact|SimpleRelation|ContactRecord":           {"controller", "registration", true},
	"IPNetRecord|rdap_url|SimpleRelation|URL":                          {"third_party", "registration", false},
	"IPNetRecord|registrant|SimpleRelation|ContactRecord":              {"controller", "registration", true},
	"IPNetRecord|technical_contact|SimpleRelation|ContactRecord":       {"third_party", "registration", true},
	"IPNetRecord|whois_server|SimpleRelation|FQDN":                     {"third_party", "registration", false},
	"Identifier|issuing_agent|SimpleRelation|ContactRecord":            {"third_party", "identity", true},
	"Identifier|issuing_authority|SimpleRelation|ContactRecord":        {"third_party", "identity", true},
	"Identifier|registration_agency|SimpleRelation|ContactRecord":      {"third_party", "identity", true},
	"Location|id|SimpleRelation|Identifier":                            {"attribute", "identity", true},
	"Netblock|contains|SimpleRelation|IPAddress":                       {"same_subject", "network", true},
	"Netblock|registration|SimpleRelation|IPNetRecord":                 {"same_subject", "registration", true},
	"Organization|account|SimpleRelation|Account":                      {"controls", "identity", true},
	"Organization|funding_source|SimpleRelation|Organization":          {"attribute", "financial", true},
	"Organization|funding_source|SimpleRelation|Person":                {"attribute", "financial", true},
	"Organization|hq_address|SimpleRelation|Location":                  {"attribute", "corporate", true},
	"Organization|id|SimpleRelation|Identifier":                        {"attribute", "identity", true},
	"Organization|legal_address|SimpleRelation|Location":               {"attribute", "corporate", true},
	"Organization|location|SimpleRelation|Location":                    {"attribute", "corporate", true},
	"Organization|member|SimpleRelation|Person":                        {"attribute", "corporate", true},
	"Organization|org_unit|SimpleRelation|Organization":                {"controls", "corporate", true},
	"Organization|social_media_profile|SimpleRelation|URL":             {"controls", "web", true},
	"Organization|subsidiary|SimpleRelation|Organization":              {"controls", "corporate", true},
	"Organization|website|SimpleRelation|URL":                          {"controls", "web", true},
	"Person|account|SimpleRelation|Account":                            {"controls", "identity", true},
	"Person|address|SimpleRelation|Location":                           {"attribute", "identity", true},
	"Person|id|SimpleRelation|Identifier":                              {"attribute", "identity", true},
	"Person|phone|SimpleRelation|Phone":                                {"attribute", "identity", true},
	"Phone|account|SimpleRelation|Account":                             {"attribute", "identity", true},
	"Phone|contact|SimpleRelation|ContactRecord":                       {"attribute", "contact", true},
	"ProductRelease|id|SimpleRelation|Identifier":                      {"attribute", "product", true},
	"ProductRelease|website|SimpleRelation|URL":                        {"controls", "web", true},
	"Product|id|SimpleRelation|Identifier":                             {"attribute", "product", true},
	"Product|manufacturer|SimpleRelation|Organization":                 {"controller", "product", true},
	"Product|release|SimpleRelation|ProductRelease":                    {"controls", "product", true},
	"Product|website|SimpleRelation|URL":                               {"controls", "web", true},
	"Service|certificate|SimpleRelation|TLSCertificate":                {"same_subject", "certificate", true},
	"Service|product_used|SimpleRelation|Product":                      {"third_party", "product", true},
	"Service|product_used|SimpleRelation|ProductRelease":               {"third_party", "product", true},
	"Service|provider|SimpleRelation|Organization":                     {"third_party", "network", true},
	"Service|terms_of_service|SimpleRelation|File":                     {"attribute", "web", true},
	"Service|terms_of_service|SimpleRelation|URL":                      {"attribute", "web", true},
	"TLSCertificate|common_name|SimpleRelation|FQDN":                   {"same_subject", "certificate", true},
	"TLSCertificate|issuer_contact|SimpleRelation|ContactRecord":       {"third_party", "certificate", true},
	"TLSCertificate|issuing_certificate_url|SimpleRelation|URL":        {"third_party", "certificate", false},
	"TLSCertificate|issuing_certificate|SimpleRelation|TLSCertificate": {"third_party", "certificate", false},
	"TLSCertificate|ocsp_server|SimpleRelation|URL":                    {"third_party", "certificate", false},
	"TLSCertificate|san_dns_name|SimpleRelation|FQDN":                  {"shared", "certificate", true},
	"TLSCertificate|san_email_address|SimpleRelation|Identifier":       {"shared", "certificate", true},
	"TLSCertificate|san_ip_address|SimpleRelation|IPAddress":           {"shared", "certificate", true},
	"TLSCertificate|san_url|SimpleRelation|URL":                        {"shared", "certificate", true},
	"TLSCertificate|subject_contact|SimpleRelation|ContactRecord":      {"controller", "certificate", true},
	"URL|domain|SimpleRelation|FQDN":                                   {"same_subject", "web", true},
	"URL|file|SimpleRelation|File":                                     {"attribute", "web", true},
	"URL|ip_address|SimpleRelation|IPAddress":                          {"infrastructure", "network", true},
	"URL|port|PortRelation|Service":                                    {"infrastructure", "network", true},
}

// vendorCatalog is the full OAM semantics table with selectors.
type vendorCatalog struct{ planCatalog }

func (vendorCatalog) Attribution(src, label, rt, dst string) (string, bool) {
	m, ok := oamSemantics[src+"|"+label+"|"+rt+"|"+dst]
	return m.Attribution, ok
}

func (vendorCatalog) Meaning(src, label, rt, dst string) (RelationMeaning, bool) {
	m, ok := oamSemantics[src+"|"+label+"|"+rt+"|"+dst]
	return m, ok
}

// Relations returns every transition in the attribution table.
func (vendorCatalog) Relations() []RelationshipSchema {
	out := make([]RelationshipSchema, 0, len(oamSemantics))
	for k := range oamSemantics {
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
		"FASTLY":       "DNS: IP addresses",
		"ultradns.net": "DNS: FQDNs",
		"pphosted.com": "DNS: FQDNs",
		"EDUCAUSE":     "Registration: contact records",
		"DigiCert Inc": "Certificate: contact records",
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
	if !strings.Contains(result.Answer, "Certificate: contact records:\n  DigiCert Inc: 1 asset(s)") {
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
	if _, ok := vendorNames(r)["FASTLY"]; !ok {
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

func TestModelThirdPartyAnswerCompilesToLens(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
			`"target_types":[],"direction":"both","purpose":"connected","answer":"third_party"}`,
	}}

	q, err := vendorAgent(model).CompileQuestion(context.Background(),
		"Tell me about the outside companies Colgate University relies on as vendors")
	if err != nil {
		t.Fatal(err)
	}
	if q.Lens != LensThirdParty || q.Subject.Name != "Colgate University" || q.Subject.Field != "" {
		t.Fatalf("third_party answer did not compile with organization resolution: %+v", q)
	}
}

func TestOrganizationSelectorUsesOrganizationResolution(t *testing.T) {
	got := organizationSubject(PlanSubject{Type: "Organization", Field: "name", Value: "Colgate University"})
	if !got.UsesOrganizationResolution() || got.Name != "Colgate University" {
		t.Fatalf("organizationSubject = %+v", got)
	}
}

func TestModelControlledAnswerFindsASN(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
			`"target_types":["AutonomousSystem"],"direction":"both","purpose":"connected","answer":"controlled"}`,
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

func TestControlledAnswerRequiresAttributableTypes(t *testing.T) {
	cat := vendorCatalog{testOAMCatalog}
	for _, tc := range []struct {
		targets []string
		ok      bool
	}{
		{[]string{"AutonomousSystem"}, true},
		{[]string{"Netblock", "FQDN"}, true},
		{nil, true},
		{[]string{"Organization"}, false},
		{[]string{"Phone"}, false},
	} {
		goal := InvestigationGoal{Subject: PlanSubject{Type: "Organization", Name: "Colgate University"},
			TargetTypes: tc.targets, Purpose: "connected", Answer: LensControlled}
		if err := validateAnswer(goal, cat); (err == nil) != tc.ok {
			t.Errorf("targets %v: err=%v, want ok=%v", tc.targets, err, tc.ok)
		}
	}
}

func TestPlannerCorrectsUnusableAnswerKind(t *testing.T) {
	model := &inspectingPlannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
			`"target_types":["Phone"],"direction":"both","purpose":"connected","answer":"controlled"}`,
		`{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
			`"target_types":["Phone"],"direction":"both","purpose":"connected","answer":"paths"}`,
	}}

	q, err := vendorAgent(model).CompileQuestion(context.Background(), "What phone numbers does Colgate list?")
	if err != nil {
		t.Fatal(err)
	}
	if q.Lens != "" || model.calls != 2 {
		t.Fatalf("calls=%d lens=%q, want a corrected paths answer", model.calls, q.Lens)
	}

	last := model.requests[1][len(model.requests[1])-1].Text
	if !strings.Contains(last, `answer "controlled" lists asset types that can be attributed`) {
		t.Errorf("correction does not explain the answer kind: %s", last)
	}
}

func TestGoalSchemaEnumeratesAnswerKinds(t *testing.T) {
	s := goalJSONSchema(testOAMCatalog, testOAMCatalog.SearchFields())
	props := s.Schema["properties"].(map[string]any)
	enum := props["answer"].(map[string]any)["enum"].([]string)
	if strings.Join(enum, ",") != strings.Join(answerKindNames(), ",") || len(enum) != len(answerKinds) {
		t.Fatalf("answer enum %v does not match the registry", enum)
	}

	prompt := goalPlannerPrompt("anything", testOAMCatalog, testOAMCatalog.SearchFields(), false, nil).Text
	for _, k := range answerKinds {
		if !strings.Contains(prompt, "- "+k.Name+" (") {
			t.Errorf("planner prompt does not describe answer kind %s", k.Name)
		}
	}
}

// extendedCatalog adds transitions the lens code has never seen, as a
// future OAM release might.
type extendedCatalog struct {
	vendorCatalog
	extra map[string]RelationMeaning
}

func (c extendedCatalog) Meaning(src, label, rt, dst string) (RelationMeaning, bool) {
	if m, ok := c.extra[src+"|"+label+"|"+rt+"|"+dst]; ok {
		return m, true
	}

	return c.vendorCatalog.Meaning(src, label, rt, dst)
}

func (c extendedCatalog) Relations() []RelationshipSchema {
	out := c.vendorCatalog.Relations()
	for k := range c.extra {
		p := strings.Split(k, "|")
		out = append(out, RelationshipSchema{SourceType: p[0], Label: p[1], RelationType: p[2], DestinationType: p[3]})
	}

	return out
}

// A new asset type and relationships, annotated only in the semantics
// table, take part in both lenses without code changes.
func TestNewOAMRelationshipsJoinLensesWithoutCode(t *testing.T) {
	cat := extendedCatalog{vendorCatalog: vendorCatalog{testOAMCatalog}, extra: map[string]RelationMeaning{
		"FQDN|hosted_on|SimpleRelation|CloudResource":            {"infrastructure", "network", true},
		"CloudResource|tenant_of|SimpleRelation|CloudAccount":    {"same_subject", "network", true},
		"CloudAccount|operated_by|SimpleRelation|Organization":   {"controller", "network", true},
		"Organization|cloud_account|SimpleRelation|CloudAccount": {"controls", "network", true},
		"CloudAccount|billing_portal|SimpleRelation|URL":         {"third_party", "financial", false},
		"CloudResource|managed_by|SimpleRelation|ContactRecord":  {"third_party", "network", true},
	}}

	g := vendorFixture()
	g.assets["bucket"] = Asset{ID: "bucket", Type: "CloudResource", Key: "assets-bucket"}
	g.assets["tenant"] = Asset{ID: "tenant", Type: "CloudAccount", Key: "tenant-1"}
	g.assets["cloudco"] = Asset{ID: "cloudco", Type: "Organization", Key: "cloudco",
		Content: map[string]any{"name": "Example Cloud"}}
	g.assets["own-acct"] = Asset{ID: "own-acct", Type: "CloudAccount", Key: "colgate-acct"}
	g.links = append(g.links,
		Relation{ID: "h1", FromID: "www.colgate.edu", ToID: "bucket", Label: "hosted_on", Type: "SimpleRelation"},
		Relation{ID: "h2", FromID: "bucket", ToID: "tenant", Label: "tenant_of", Type: "SimpleRelation"},
		Relation{ID: "h3", FromID: "tenant", ToID: "cloudco", Label: "operated_by", Type: "SimpleRelation"},
		Relation{ID: "h4", FromID: "colgate", ToID: "own-acct", Label: "cloud_account", Type: "SimpleRelation"})
	agent := Agent{Runner: ToolRunner{Graph: g, Catalog: cat, Limits: DefaultLimits()}}

	result, err := agent.AskQuery(context.Background(),
		thirdPartyQuery("", PlanSubject{Type: "Organization", Name: "Colgate University"}, SourceCaller),
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if kind := vendorNames(result.ThirdPartyReport)["Example Cloud"]; kind != "Network: cloud resources" {
		t.Errorf("new hosting relationship not reported: %v", vendorNames(result.ThirdPartyReport))
	}

	q := Query{Version: QueryVersion, Subject: PlanSubject{Type: "Organization", Name: "Colgate University"},
		Traversal: TraversalExplore, TargetTypes: []string{"CloudAccount"}, Direction: "both",
		Purpose: "connected", Lens: LensControlled, Source: SourceCaller}
	if !controlledReachable(cat, q.TargetTypes) {
		t.Fatal("new controls relationship does not make CloudAccount attributable")
	}

	result, err = agent.AskQuery(context.Background(), q, AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r := result.ControlledReport; len(r.Matches) != 1 || r.Matches[0].Nodes[1].ID != "own-acct" {
		t.Fatalf("controlled lens did not use the new relationship: %+v", r)
	}
}

// Qwen answered the ASN question with answer "paths"; an Organization goal
// for attributable types still runs the controlled lens.
func TestAttributableOrganizationGoalRunsControlledLens(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
			`"target_types":["AutonomousSystem"],"direction":"both","purpose":"connected","answer":"paths"}`,
	}}

	result, err := vendorAgent(model).AskAdaptive(context.Background(),
		"Which ASN is associated to the Colgate University organization?", AdaptiveOptions{GuidanceRounds: 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.Query == nil || result.Query.Lens != LensControlled || model.calls != 1 {
		t.Fatalf("calls=%d query=%+v, want the controlled lens after one planning call", model.calls, result.Query)
	}
}

// The subject's owner is found even when many certificates and URLs share
// its name and lead nowhere. An Organization's website edge makes every URL
// look one step from an owner, so a budgeted best-first search spent its
// budget on colgate.edu's URLs and missed the registrant (eval 2026-11-09).
func TestDomainOwnerFoundPastManyCertificates(t *testing.T) {
	g := vendorFixture()
	for i := 0; i < 60; i++ {
		cert, url := fmt.Sprintf("cn-cert-%02d", i), fmt.Sprintf("url-%02d", i)
		g.assets[cert] = Asset{ID: cert, Type: "TLSCertificate", Key: cert}
		g.assets[url] = Asset{ID: url, Type: "URL", Key: "https://colgate.edu/" + url}
		g.links = append(g.links,
			Relation{ID: "cn-" + cert, FromID: cert, ToID: "colgate.edu", Label: "common_name", Type: "SimpleRelation"},
			Relation{ID: "dom-" + url, FromID: url, ToID: "colgate.edu", Label: "domain", Type: "SimpleRelation"})
	}

	agent := Agent{Runner: ToolRunner{Graph: g, Catalog: vendorCatalog{testOAMCatalog}, Limits: DefaultLimits()}}
	result, err := agent.AskQuery(context.Background(),
		thirdPartyQuery("", PlanSubject{Type: "FQDN", Field: "name", Value: "colgate.edu"}, SourceCaller),
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r := result.ThirdPartyReport; len(r.Owners) != 1 || r.Owners[0] != "Colgate University" {
		t.Fatalf("owner not found: %+v", r.Owners)
	}
	for name := range vendorNames(result.ThirdPartyReport) {
		if strings.Contains(strings.ToLower(name), "colgate") {
			t.Errorf("the subject's own organization is listed as a vendor: %s", name)
		}
	}
}

func TestTableColumnsAreValidated(t *testing.T) {
	types := catalogTypes(vendorCatalog{testOAMCatalog}.Relations(), nil)
	for _, tc := range []struct {
		cols []TableColumn
		ok   bool
	}{
		{[]TableColumn{{Type: "IPAddress"}, {Type: "Organization", Role: ColumnController}}, true},
		{nil, false},
		{[]TableColumn{{Type: "Website"}}, false},
		{[]TableColumn{{Type: "IPAddress", Role: ColumnController}}, false},
		{[]TableColumn{{Type: "IPAddress", Role: "owner"}}, false},
		{[]TableColumn{{Type: "Organization", Role: ColumnController}, {Type: "Organization", Role: ColumnController}},
			false},
		{[]TableColumn{{Type: "IPAddress"}, {Type: "IPAddress"}}, false},
		{[]TableColumn{{Type: "Organization", Role: ColumnController}}, true},
	} {
		if err := validateColumns(tc.cols, types); (err == nil) != tc.ok {
			t.Errorf("columns %+v: err=%v, want ok=%v", tc.cols, err, tc.ok)
		}
	}
}

func TestTableAnswerNeedsAttributableRows(t *testing.T) {
	goal := InvestigationGoal{Subject: PlanSubject{Type: "Organization", Name: "Colgate University"},
		TargetTypes: []string{"Phone"}, Purpose: "connected", Answer: LensTable,
		Columns: []TableColumn{{Type: "Organization", Role: ColumnController}}}
	if err := validateAnswer(goal, vendorCatalog{testOAMCatalog}); err == nil {
		t.Fatal("a table of unattributable rows was accepted")
	}

	goal.TargetTypes = []string{"URL"}
	if err := validateAnswer(goal, vendorCatalog{testOAMCatalog}); err != nil {
		t.Fatalf("valid table rejected: %v", err)
	}
}

// Qwen put the subject's type in the row slot of a table three times; the
// prompt and the correction now list the row types an owner can control.
func TestTableRowTypeCorrectionListsControllableTypes(t *testing.T) {
	bad := `{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
		`"target_types":["Organization"],"direction":"both","purpose":"connected","answer":"table",` +
		`"columns":[{"type":"IPAddress","role":""},{"type":"Organization","role":"controller"}]}`
	good := strings.Replace(bad, `"target_types":["Organization"]`, `"target_types":["URL"]`, 1)
	agent := func(model Model) Agent {
		return Agent{Model: model, Runner: ToolRunner{Graph: campusWebFixture(), Catalog: vendorCatalog{testOAMCatalog},
			Limits: DefaultLimits()}}
	}

	// The question names websites, so the controller row type is repaired
	// to URL without a correction.
	model := &inspectingPlannerModel{replies: []string{bad}}
	q, err := agent(model).CompileQuestion(context.Background(),
		"Please create a table with each website, it's IP address, and hosting provider within Colgate University?")
	if err != nil {
		t.Fatal(err)
	}
	if q.Lens != LensTable || q.TargetTypes[0] != "URL" || len(model.requests) != 1 {
		t.Fatalf("row type not repaired in one call: %+v after %d calls", q, len(model.requests))
	}

	prompt := model.requests[0][0].Text
	if !strings.Contains(prompt, "Types an owner can control:") || !strings.Contains(prompt, "URL") {
		t.Error("planner prompt does not list controllable row types")
	}

	// A question that names no type an owner controls gets the correction.
	model = &inspectingPlannerModel{replies: []string{bad, good}}
	q, err = agent(model).CompileQuestion(context.Background(),
		"Please create a table of Colgate University and its hosting providers")
	if err != nil {
		t.Fatal(err)
	}
	if q.TargetTypes[0] != "URL" || len(model.requests) != 2 || len(q.PlanCorrections) != 1 {
		t.Fatalf("corrected table = %+v after %d calls", q, len(model.requests))
	}

	correction := model.requests[1][len(model.requests[1])-1].Text
	for _, want := range []string{
		"URL for websites",
		"Row types an owner can control:",
		"Netblock",
		"role controller",
	} {
		if !strings.Contains(correction, want) {
			t.Errorf("correction lacks %q: %s", want, correction)
		}
	}
}

// Live eval: Qwen returned three controller columns and no IP address
// column. The repeats collapse and the IP address column the question
// names is added, so no correction call is needed.
func TestRepeatedControllerColumnsAreRepaired(t *testing.T) {
	ctl := `{"type":"Organization","role":"controller"}`
	bad := `{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
		`"target_types":["URL"],"direction":"both","purpose":"connected","answer":"table",` +
		`"columns":[` + ctl + `,` + ctl + `,` + ctl + `]}`
	model := &plannerModel{replies: []string{bad}}

	q, err := Agent{Model: model, Runner: ToolRunner{Graph: campusWebFixture(), Catalog: vendorCatalog{testOAMCatalog},
		Limits: DefaultLimits()}}.CompileQuestion(context.Background(),
		"Please create a table with each website, it's IP address, and hosting provider within Colgate University?")
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 1 || len(q.Columns) != 2 || q.Columns[0].Type != "IPAddress" ||
		q.Columns[1].Role != ColumnController {
		t.Fatalf("calls=%d columns=%+v, want IPAddress then controller after one call", model.calls, q.Columns)
	}
}

// Live eval plan: "with URL, then IPAddress, then controlling Organization"
// in a table of URLs; the URL column only repeats the row.
func TestTableDropsColumnsRepeatingTheRow(t *testing.T) {
	goal := InvestigationGoal{TargetTypes: []string{"URL"}, Columns: []TableColumn{{Type: "URL"}, {Type: "IPAddress"},
		{Type: "Organization", Role: ColumnController}}}
	if cols := tableColumns(goal, nil); len(cols) != 2 || cols[0].Type != "IPAddress" {
		t.Fatalf("columns = %+v, want IPAddress then controller", cols)
	}

	goal.Columns = []TableColumn{{Type: "URL"}}
	if cols := tableColumns(goal, nil); len(cols) != 1 {
		t.Fatalf("the only column was dropped: %+v", cols)
	}
}

// Live eval plan: "with controlling Organization" only, for a question that
// names IP addresses. The IP address column is added before the
// controller, so the controller is the IP address's hosting provider.
func TestTableAddsColumnsTheQuestionMentions(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
			`"target_types":["URL"],"direction":"both","purpose":"connected","answer":"table",` +
			`"columns":[{"type":"Organization","role":"controller"}]}`,
	}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: campusWebFixture(), Catalog: vendorCatalog{testOAMCatalog},
		Limits: DefaultLimits()}}

	result, err := agent.AskAdaptive(context.Background(),
		"Please create a table with each website, it's IP address, and hosting provider that's within the Colgate "+
			"University organization?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	cols := result.Query.Columns
	if len(cols) != 2 || cols[0].Type != "IPAddress" || cols[1].Role != ColumnController {
		t.Fatalf("columns = %+v, want IPAddress then controller", cols)
	}
	if !strings.Contains(result.Answer, "| https://www.colgate.edu | 151.101.1.1 | FASTLY |") {
		t.Errorf("table does not show the hosting provider of the IP address:\n%s", result.Answer)
	}
	if model.calls != 1 {
		t.Errorf("repairing the chain used %d model calls, want 1", model.calls)
	}
}

func TestMentionedTypesPreferLongestPhrase(t *testing.T) {
	cat := vendorCatalog{testOAMCatalog}
	got := strings.Join(mentionedTypes("each website, it's IP address, and hosting provider", cat), ",")
	if got != "IPAddress,URL" {
		t.Errorf("mentioned = %q, want IPAddress and URL (website), not Location for \"address\"", got)
	}
	if got := strings.Join(mentionedTypes("list the netblocks and ASNs",
		cat), ","); got != "AutonomousSystem,Netblock" {
		t.Errorf("mentioned = %q", got)
	}
}

// structuredPlanner returns replies in order through GenerateStructured
// and records the schema of each call.
type structuredPlanner struct {
	replies []string
	schemas []JSONSchema
}

func (m *structuredPlanner) Generate(context.Context, []Message, []ToolSpec) (Response, error) {
	return Response{}, errors.New("structured generation expected")
}

func (m *structuredPlanner) GenerateStructured(_ context.Context, _ []Message, s JSONSchema) (Response, error) {
	i := len(m.schemas)
	m.schemas = append(m.schemas, s)
	if i >= len(m.replies) {
		i = len(m.replies) - 1
	}

	return Response{Text: m.replies[i]}, nil
}

// After a table with an invalid row type, the retry's schema allows only
// the table answer and controllable row types, so a schema-enforcing
// provider cannot repeat Qwen's mistake.
func TestTableRetryNarrowsTheSchema(t *testing.T) {
	bad := `{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
		`"target_types":["Organization"],"direction":"both","purpose":"connected","relationships":[],` +
		`"path_rule":"","answer":"table","columns":[{"type":"IPAddress","role":""},` +
		`{"type":"Organization","role":"controller"}]}`
	good := strings.Replace(bad, `"target_types":["Organization"]`, `"target_types":["URL"]`, 1)
	model := &structuredPlanner{replies: []string{bad, good}}

	// The question names no type an owner controls, so the row type cannot
	// be repaired from it and the retry is needed.
	q, err := Agent{Model: model, Runner: ToolRunner{Graph: campusWebFixture(), Catalog: vendorCatalog{testOAMCatalog},
		Limits: DefaultLimits()}}.CompileQuestion(context.Background(),
		"Please create a table of Colgate University and its hosting providers")
	if err != nil || q.Lens != LensTable || len(model.schemas) != 2 {
		t.Fatalf("q=%+v err=%v calls=%d", q, err, len(model.schemas))
	}

	props := model.schemas[1].Schema["properties"].(map[string]any)
	if enum := props["answer"].(map[string]any)["enum"].([]string); len(enum) != 1 || enum[0] != LensTable {
		t.Errorf("retry answer enum = %v, want [table]", enum)
	}

	rows := props["target_types"].(map[string]any)["items"].(map[string]any)["enum"].([]string)
	if contains(rows, "Organization") || !contains(rows, "URL") || !contains(rows, "Netblock") {
		t.Errorf("retry row types = %v, want controllable types without Organization", rows)
	}
	if props["target_types"].(map[string]any)["maxItems"] != 1 {
		t.Error("retry allows more than one row type")
	}

	first := model.schemas[0].Schema["properties"].(map[string]any)["answer"].(map[string]any)["enum"].([]string)
	if len(first) != len(answerKinds) {
		t.Errorf("first attempt was narrowed: %v", first)
	}
}

// A rejected controlled answer may need another kind, so its retry keeps
// the full schema.
func TestControlledRetryKeepsTheFullSchema(t *testing.T) {
	bad := `{"subject":{"type":"Organization","field":"name","value":"Colgate University"},` +
		`"target_types":["Phone"],"direction":"both","purpose":"connected","relationships":[],"path_rule":"",` +
		`"answer":"controlled","columns":[]}`
	good := strings.Replace(bad, `"answer":"controlled"`, `"answer":"paths"`, 1)
	model := &structuredPlanner{replies: []string{bad, good}}

	if _, err := (Agent{Model: model, Runner: ToolRunner{Graph: campusWebFixture(),
		Catalog: vendorCatalog{testOAMCatalog}, Limits: DefaultLimits()}}).CompileQuestion(context.Background(),
		"What phone numbers does Colgate list?"); err != nil {
		t.Fatal(err)
	}

	enum := model.schemas[1].Schema["properties"].(map[string]any)["answer"].(map[string]any)["enum"].([]string)
	if len(enum) != len(answerKinds) {
		t.Errorf("controlled retry narrowed the answer kinds: %v", enum)
	}
}

func TestRepairColumnsReadsMisplacedControllersAsTypes(t *testing.T) {
	got := repairColumns([]TableColumn{{Type: "Service", Role: ColumnController},
		{Type: "Organization", Role: ColumnController}, {Type: "Organization", Role: ColumnController}})
	want := []TableColumn{{Type: "Service"}, {Type: "Organization", Role: ColumnController}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("repaired = %+v, want %+v", got, want)
	}
}

// The schema allows exactly two column shapes, so a schema-enforcing
// provider cannot pair the controller role with a non-organization type.
func TestColumnSchemaAllowsTwoShapes(t *testing.T) {
	props := goalJSONSchema(testOAMCatalog, testOAMCatalog.SearchFields()).Schema["properties"].(map[string]any)
	shapes := props["columns"].(map[string]any)["items"].(map[string]any)["anyOf"].([]any)
	if len(shapes) != 2 {
		t.Fatalf("column shapes = %d, want 2", len(shapes))
	}

	controller := shapes[1].(map[string]any)["properties"].(map[string]any)
	if fmt.Sprint(controller["type"].(map[string]any)["enum"]) != "[Organization]" ||
		fmt.Sprint(controller["role"].(map[string]any)["enum"]) != "[controller]" {
		t.Errorf("controller shape = %v", controller)
	}
}

func TestRelationDetailShowsPorts(t *testing.T) {
	e := Relation{Label: "port", Content: map[string]any{"port_number": 443, "protocol": "tcp"}}
	if got := relationDetail(e); got != "443/tcp" {
		t.Errorf("detail = %q, want 443/tcp", got)
	}
	if got := relationDetail(Relation{Label: "node"}); got != "" {
		t.Errorf("detail = %q for a relation without fields", got)
	}

	w := witnessOf(e, Asset{ID: "a", Type: "FQDN", Key: "www.example.com"}, Asset{ID: "b", Type: "Service", Key: "x"})
	if line := (EvidenceItem{ID: "E1", WitnessEdge: w}).Line(); !strings.Contains(line, "--port 443/tcp-->") {
		t.Errorf("evidence line lacks the port: %s", line)
	}
}

func TestReservedName(t *testing.T) {
	for name, want := range map[string]bool{"msv1.invalid": true, "host.test.": true, "localhost": true,
		"www.example": true, "example.com": false, "invalidate.net": false} {
		if got := reservedName(name); got != want {
			t.Errorf("reservedName(%q) = %v, want %v", name, got, want)
		}
	}
}
