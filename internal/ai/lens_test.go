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

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

func vendorAgent(model llm.Model) Agent {
	return Agent{Model: model, Runner: ToolRunner{Graph: graphtest.VendorFixture(), Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		Limits: graph.DefaultLimits()}}
}

func vendorNames(r *lens.ThirdPartyReport) map[string]string {
	out := map[string]string{}
	for _, v := range r.Vendors {
		out[v.Vendor] = v.Kind
	}

	return out
}

func TestThirdPartyQuestionCompilesWithoutModel(t *testing.T) {
	for question, want := range map[string]PlanSubject{
		"Which third-party vendors are being used by the OWASP Foundation organization?": {
			Type: "Organization", Name: "OWASP Foundation"},
		"What vendors are used by OWASP Foundation?":  {Type: "Organization", Name: "OWASP Foundation"},
		"List the third-party providers of owasp.org": {Type: "FQDN", Field: "name", Value: "owasp.org"},
		"Which suppliers are relied upon by OWASP Foundation's": {
			Type: "Organization", Name: "OWASP Foundation"},
	} {
		q, ok := deterministicThirdPartyQuery(question)
		if !ok || q.Lens != lens.LensThirdParty || q.Subject != want {
			t.Errorf("%q compiled to %+v (ok=%v), want subject %+v", question, q, ok, want)
		}
	}
}

func TestThirdPartyLensFindsVendorsOfOrganization(t *testing.T) {
	model := &plannerModel{}
	result, err := vendorAgent(model).AskAdaptive(context.Background(),
		"Which third-party vendors are being used by the OWASP Foundation organization?", AdaptiveOptions{})
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
	for _, own := range []string{"OWASP Foundation", "owasp.org", "Utica University", "cloudflare.com"} {
		if _, ok := got[own]; ok {
			t.Errorf("%s reported as a vendor of OWASP Foundation", own)
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
		thirdPartyQuery("", PlanSubject{Type: "FQDN", Field: "name", Value: "owasp.org"}, SourceCaller),
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	r := result.ThirdPartyReport
	if r == nil || len(r.Owners) != 1 || r.Owners[0] != "OWASP Foundation" {
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
	g := graphtest.VendorFixture()
	g.Links = nil
	agent := Agent{Runner: ToolRunner{Graph: g, Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, Limits: graph.DefaultLimits()}}

	result, err := agent.AskQuery(context.Background(),
		thirdPartyQuery("", PlanSubject{Type: "Organization", Name: "OWASP Foundation"}, SourceCaller),
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Answer, "No assets are documented as controlled by OWASP Foundation") {
		t.Fatalf("empty footprint not explained: %s", result.Answer)
	}
}

func TestModelThirdPartyAnswerCompilesToLens(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"OWASP Foundation"},` +
			`"target_types":[],"direction":"both","purpose":"connected","answer":"third_party"}`,
	}}

	q, err := vendorAgent(model).CompileQuestion(context.Background(),
		"Tell me about the outside companies OWASP Foundation relies on as vendors")
	if err != nil {
		t.Fatal(err)
	}
	if q.Lens != lens.LensThirdParty || q.Subject.Name != "OWASP Foundation" || q.Subject.Field != "" {
		t.Fatalf("third_party answer did not compile with organization resolution: %+v", q)
	}
}

func TestOrganizationSelectorUsesOrganizationResolution(t *testing.T) {
	got := organizationSubject(PlanSubject{Type: "Organization", Field: "name", Value: "OWASP Foundation"})
	if !got.UsesOrganizationResolution() || got.Name != "OWASP Foundation" {
		t.Fatalf("organizationSubject = %+v", got)
	}
}

func TestModelControlledAnswerFindsASN(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"OWASP Foundation"},` +
			`"target_types":["AutonomousSystem"],"direction":"both","purpose":"connected","answer":"controlled"}`,
	}}

	result, err := vendorAgent(model).AskAdaptive(context.Background(),
		"Which ASN is associated to the OWASP Foundation organization?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 1 || result.Query == nil || result.Query.Lens != lens.LensControlled {
		t.Fatalf("calls=%d query=%+v, want one planning call and the controlled lens", model.calls, result.Query)
	}

	r := result.ControlledReport
	if r == nil || len(r.Matches) != 1 {
		t.Fatalf("want exactly AS64500, got %+v", r)
	}

	last := r.Matches[0].Nodes[len(r.Matches[0].Nodes)-1]
	if last.ID != "as-own" || len(r.Matches[0].Edges) != 3 {
		t.Errorf("wrong ASN or path: %s", lens.WitnessChain(r.Matches[0]))
	}
	if r.FootprintTypes["FQDN"] != 0 || r.FootprintTypes["URL"] != 0 {
		t.Errorf("walk read assets that cannot lead to an ASN: %v", r.FootprintTypes)
	}
	if !strings.Contains(result.Answer, "Found 1 AutonomousSystem asset(s) controlled by OWASP Foundation") ||
		!strings.Contains(result.Answer, "<--registration-- AutonomousSystem 64500") {
		t.Errorf("answer does not cite the witnessed path:\n%s", result.Answer)
	}
	if result.Diagram == "" {
		t.Error("controlled lens did not render a diagram")
	}
}

func TestControlledLensExcludesThirdPartyNetworks(t *testing.T) {
	q := Query{Version: QueryVersion, Subject: PlanSubject{Type: "Organization", Name: "OWASP Foundation"},
		Traversal: TraversalExplore, TargetTypes: []string{"Netblock", "AutonomousSystem"}, Direction: "both",
		Purpose: "connected", Lens: lens.LensControlled, Source: SourceCaller}

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
	cat := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
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
		goal := InvestigationGoal{Subject: PlanSubject{Type: "Organization", Name: "OWASP Foundation"},
			TargetTypes: tc.targets, Purpose: "connected", Answer: lens.LensControlled}
		if err := validateAnswer(goal, cat); (err == nil) != tc.ok {
			t.Errorf("targets %v: err=%v, want ok=%v", tc.targets, err, tc.ok)
		}
	}
}

func TestPlannerCorrectsUnusableAnswerKind(t *testing.T) {
	model := &inspectingPlannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"OWASP Foundation"},` +
			`"target_types":["Phone"],"direction":"both","purpose":"connected","answer":"controlled"}`,
		`{"subject":{"type":"Organization","field":"name","value":"OWASP Foundation"},` +
			`"target_types":["Phone"],"direction":"both","purpose":"connected","answer":"paths"}`,
	}}

	q, err := vendorAgent(model).CompileQuestion(context.Background(), "What phone numbers does OWASP list?")
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
	s := goalJSONSchema(graphtest.TestOAMCatalog, graphtest.TestOAMCatalog.SearchFields())
	props := s.Schema["properties"].(map[string]any)
	enum := props["answer"].(map[string]any)["enum"].([]string)
	if strings.Join(enum, ",") != strings.Join(answerKindNames(), ",") || len(enum) != len(answerKinds) {
		t.Fatalf("answer enum %v does not match the registry", enum)
	}

	prompt := goalPlannerPrompt("anything", graphtest.TestOAMCatalog, graphtest.TestOAMCatalog.SearchFields(), false, nil).Text
	for _, k := range answerKinds {
		if !strings.Contains(prompt, "- "+k.Name+" (") {
			t.Errorf("planner prompt does not describe answer kind %s", k.Name)
		}
	}
}

// extendedCatalog adds transitions the lens code has never seen, as a
// future OAM release might.
type extendedCatalog struct {
	graphtest.VendorCatalog
	extra map[string]graph.RelationMeaning
}

func (c extendedCatalog) Meaning(src, label, rt, dst string) (graph.RelationMeaning, bool) {
	if m, ok := c.extra[src+"|"+label+"|"+rt+"|"+dst]; ok {
		return m, true
	}

	return c.VendorCatalog.Meaning(src, label, rt, dst)
}

func (c extendedCatalog) Relations() []graph.RelationshipSchema {
	out := c.VendorCatalog.Relations()
	for k := range c.extra {
		p := strings.Split(k, "|")
		out = append(out, graph.RelationshipSchema{SourceType: p[0], Label: p[1], RelationType: p[2], DestinationType: p[3]})
	}

	return out
}

// A new asset type and relationships, annotated only in the semantics
// table, take part in both lenses without code changes.
func TestNewOAMRelationshipsJoinLensesWithoutCode(t *testing.T) {
	cat := extendedCatalog{VendorCatalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, extra: map[string]graph.RelationMeaning{
		"FQDN|hosted_on|SimpleRelation|CloudResource":            {Attribution: "infrastructure", Purpose: "network", Vendor: true},
		"CloudResource|tenant_of|SimpleRelation|CloudAccount":    {Attribution: "same_subject", Purpose: "network", Vendor: true},
		"CloudAccount|operated_by|SimpleRelation|Organization":   {Attribution: "controller", Purpose: "network", Vendor: true},
		"Organization|cloud_account|SimpleRelation|CloudAccount": {Attribution: "controls", Purpose: "network", Vendor: true},
		"CloudAccount|billing_portal|SimpleRelation|URL":         {Attribution: "third_party", Purpose: "financial", Vendor: false},
		"CloudResource|managed_by|SimpleRelation|ContactRecord":  {Attribution: "third_party", Purpose: "network", Vendor: true},
	}}

	g := graphtest.VendorFixture()
	g.Assets["bucket"] = graph.Asset{ID: "bucket", Type: "CloudResource", Key: "assets-bucket"}
	g.Assets["tenant"] = graph.Asset{ID: "tenant", Type: "CloudAccount", Key: "tenant-1"}
	g.Assets["cloudco"] = graph.Asset{ID: "cloudco", Type: "Organization", Key: "cloudco",
		Content: map[string]any{"name": "Example Cloud"}}
	g.Assets["own-acct"] = graph.Asset{ID: "own-acct", Type: "CloudAccount", Key: "owasp-acct"}
	g.Links = append(g.Links,
		graph.Relation{ID: "h1", FromID: "www.owasp.org", ToID: "bucket", Label: "hosted_on", Type: "SimpleRelation"},
		graph.Relation{ID: "h2", FromID: "bucket", ToID: "tenant", Label: "tenant_of", Type: "SimpleRelation"},
		graph.Relation{ID: "h3", FromID: "tenant", ToID: "cloudco", Label: "operated_by", Type: "SimpleRelation"},
		graph.Relation{ID: "h4", FromID: "owasp", ToID: "own-acct", Label: "cloud_account", Type: "SimpleRelation"})
	agent := Agent{Runner: ToolRunner{Graph: g, Catalog: cat, Limits: graph.DefaultLimits()}}

	result, err := agent.AskQuery(context.Background(),
		thirdPartyQuery("", PlanSubject{Type: "Organization", Name: "OWASP Foundation"}, SourceCaller),
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if kind := vendorNames(result.ThirdPartyReport)["Example Cloud"]; kind != "Network: cloud resources" {
		t.Errorf("new hosting relationship not reported: %v", vendorNames(result.ThirdPartyReport))
	}

	q := Query{Version: QueryVersion, Subject: PlanSubject{Type: "Organization", Name: "OWASP Foundation"},
		Traversal: TraversalExplore, TargetTypes: []string{"CloudAccount"}, Direction: "both",
		Purpose: "connected", Lens: lens.LensControlled, Source: SourceCaller}
	if !lens.ControlledReachable(cat, q.TargetTypes) {
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
		`{"subject":{"type":"Organization","field":"name","value":"OWASP Foundation"},` +
			`"target_types":["AutonomousSystem"],"direction":"both","purpose":"connected","answer":"paths"}`,
	}}

	result, err := vendorAgent(model).AskAdaptive(context.Background(),
		"Which ASN is associated to the OWASP Foundation organization?", AdaptiveOptions{GuidanceRounds: 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.Query == nil || result.Query.Lens != lens.LensControlled || model.calls != 1 {
		t.Fatalf("calls=%d query=%+v, want the controlled lens after one planning call", model.calls, result.Query)
	}
}

// The subject's owner is found even when many certificates and URLs share
// its name and lead nowhere. An Organization's website edge makes every URL
// look one step from an owner, so a budgeted best-first search spent its
// budget on owasp.org's URLs and missed the registrant (eval 2026-11-09).
func TestDomainOwnerFoundPastManyCertificates(t *testing.T) {
	g := graphtest.VendorFixture()
	for i := 0; i < 60; i++ {
		cert, url := fmt.Sprintf("cn-cert-%02d", i), fmt.Sprintf("url-%02d", i)
		g.Assets[cert] = graph.Asset{ID: cert, Type: "TLSCertificate", Key: cert}
		g.Assets[url] = graph.Asset{ID: url, Type: "URL", Key: "https://owasp.org/" + url}
		g.Links = append(g.Links,
			graph.Relation{ID: "cn-" + cert, FromID: cert, ToID: "owasp.org", Label: "common_name", Type: "SimpleRelation"},
			graph.Relation{ID: "dom-" + url, FromID: url, ToID: "owasp.org", Label: "domain", Type: "SimpleRelation"})
	}

	agent := Agent{Runner: ToolRunner{Graph: g, Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, Limits: graph.DefaultLimits()}}
	result, err := agent.AskQuery(context.Background(),
		thirdPartyQuery("", PlanSubject{Type: "FQDN", Field: "name", Value: "owasp.org"}, SourceCaller),
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r := result.ThirdPartyReport; len(r.Owners) != 1 || r.Owners[0] != "OWASP Foundation" {
		t.Fatalf("owner not found: %+v", r.Owners)
	}
	for name := range vendorNames(result.ThirdPartyReport) {
		if strings.Contains(strings.ToLower(name), "owasp") {
			t.Errorf("the subject's own organization is listed as a vendor: %s", name)
		}
	}
}

func TestTableAnswerNeedsAttributableRows(t *testing.T) {
	goal := InvestigationGoal{Subject: PlanSubject{Type: "Organization", Name: "OWASP Foundation"},
		TargetTypes: []string{"Phone"}, Purpose: "connected", Answer: lens.LensTable,
		Columns: []lens.TableColumn{{Type: "Organization", Role: lens.ColumnController}}}
	if err := validateAnswer(goal, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}); err == nil {
		t.Fatal("a table of unattributable rows was accepted")
	}

	goal.TargetTypes = []string{"URL"}
	if err := validateAnswer(goal, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}); err != nil {
		t.Fatalf("valid table rejected: %v", err)
	}
}

// Qwen put the subject's type in the row slot of a table three times; the
// prompt and the correction now list the row types an owner can control.
func TestTableRowTypeCorrectionListsControllableTypes(t *testing.T) {
	bad := `{"subject":{"type":"Organization","field":"name","value":"OWASP Foundation"},` +
		`"target_types":["Organization"],"direction":"both","purpose":"connected","answer":"table",` +
		`"columns":[{"type":"IPAddress","role":""},{"type":"Organization","role":"controller"}]}`
	good := strings.Replace(bad, `"target_types":["Organization"]`, `"target_types":["URL"]`, 1)
	agent := func(model llm.Model) Agent {
		return Agent{Model: model, Runner: ToolRunner{Graph: graphtest.CampusWebFixture(), Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
			Limits: graph.DefaultLimits()}}
	}

	// The question names websites, so the controller row type is repaired
	// to URL without a correction.
	model := &inspectingPlannerModel{replies: []string{bad}}
	q, err := agent(model).CompileQuestion(context.Background(),
		"Please create a table with each website, it's IP address, and hosting provider within OWASP Foundation?")
	if err != nil {
		t.Fatal(err)
	}
	if q.Lens != lens.LensTable || q.TargetTypes[0] != "URL" || len(model.requests) != 1 {
		t.Fatalf("row type not repaired in one call: %+v after %d calls", q, len(model.requests))
	}

	prompt := model.requests[0][0].Text
	if !strings.Contains(prompt, "Types an owner can control:") || !strings.Contains(prompt, "URL") {
		t.Error("planner prompt does not list controllable row types")
	}

	// A question that names no type an owner controls gets the correction.
	model = &inspectingPlannerModel{replies: []string{bad, good}}
	q, err = agent(model).CompileQuestion(context.Background(),
		"Please create a table of OWASP Foundation and its hosting providers")
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
	bad := `{"subject":{"type":"Organization","field":"name","value":"OWASP Foundation"},` +
		`"target_types":["URL"],"direction":"both","purpose":"connected","answer":"table",` +
		`"columns":[` + ctl + `,` + ctl + `,` + ctl + `]}`
	model := &plannerModel{replies: []string{bad}}

	q, err := Agent{Model: model, Runner: ToolRunner{Graph: graphtest.CampusWebFixture(), Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		Limits: graph.DefaultLimits()}}.CompileQuestion(context.Background(),
		"Please create a table with each website, it's IP address, and hosting provider within OWASP Foundation?")
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 1 || len(q.Columns) != 2 || q.Columns[0].Type != "IPAddress" ||
		q.Columns[1].Role != lens.ColumnController {
		t.Fatalf("calls=%d columns=%+v, want IPAddress then controller after one call", model.calls, q.Columns)
	}
}

// Live eval plan: "with URL, then IPAddress, then controlling Organization"
// in a table of URLs; the URL column only repeats the row.
func TestTableDropsColumnsRepeatingTheRow(t *testing.T) {
	goal := InvestigationGoal{TargetTypes: []string{"URL"}, Columns: []lens.TableColumn{{Type: "URL"}, {Type: "IPAddress"},
		{Type: "Organization", Role: lens.ColumnController}}}
	if cols := tableColumns(goal, nil); len(cols) != 2 || cols[0].Type != "IPAddress" {
		t.Fatalf("columns = %+v, want IPAddress then controller", cols)
	}

	goal.Columns = []lens.TableColumn{{Type: "URL"}}
	if cols := tableColumns(goal, nil); len(cols) != 1 {
		t.Fatalf("the only column was dropped: %+v", cols)
	}
}

// Live eval plan: "with controlling Organization" only, for a question that
// names IP addresses. The IP address column is added before the
// controller, so the controller is the IP address's hosting provider.
func TestTableAddsColumnsTheQuestionMentions(t *testing.T) {
	model := &plannerModel{replies: []string{
		`{"subject":{"type":"Organization","field":"name","value":"OWASP Foundation"},` +
			`"target_types":["URL"],"direction":"both","purpose":"connected","answer":"table",` +
			`"columns":[{"type":"Organization","role":"controller"}]}`,
	}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: graphtest.CampusWebFixture(), Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		Limits: graph.DefaultLimits()}}

	result, err := agent.AskAdaptive(context.Background(),
		"Please create a table with each website, it's IP address, and hosting provider that's within the OWASP "+
			"University organization?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	cols := result.Query.Columns
	if len(cols) != 2 || cols[0].Type != "IPAddress" || cols[1].Role != lens.ColumnController {
		t.Fatalf("columns = %+v, want IPAddress then controller", cols)
	}
	if !strings.Contains(result.Answer, "| https://www.owasp.org | 151.101.1.1 | FASTLY |") {
		t.Errorf("table does not show the hosting provider of the IP address:\n%s", result.Answer)
	}
	if model.calls != 1 {
		t.Errorf("repairing the chain used %d model calls, want 1", model.calls)
	}
}

func TestMentionedTypesPreferLongestPhrase(t *testing.T) {
	cat := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
	got := strings.Join(mentionedTypes("each website, it's IP address, and hosting provider", cat), ",")
	if got != "IPAddress,URL" {
		t.Errorf("mentioned = %q, want IPAddress and URL (website), not StreetAddress for \"address\"", got)
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
	schemas []llm.JSONSchema
}

func (m *structuredPlanner) Generate(context.Context, []llm.Message, []llm.ToolSpec) (llm.Response, error) {
	return llm.Response{}, errors.New("structured generation expected")
}

func (m *structuredPlanner) GenerateStructured(_ context.Context, _ []llm.Message, s llm.JSONSchema) (llm.Response, error) {
	i := len(m.schemas)
	m.schemas = append(m.schemas, s)
	if i >= len(m.replies) {
		i = len(m.replies) - 1
	}

	return llm.Response{Text: m.replies[i]}, nil
}

// After a table with an invalid row type, the retry's schema allows only
// the table answer and controllable row types, so a schema-enforcing
// provider cannot repeat Qwen's mistake.
func TestTableRetryNarrowsTheSchema(t *testing.T) {
	bad := `{"subject":{"type":"Organization","field":"name","value":"OWASP Foundation"},` +
		`"target_types":["Organization"],"direction":"both","purpose":"connected","relationships":[],` +
		`"path_rule":"","answer":"table","columns":[{"type":"IPAddress","role":""},` +
		`{"type":"Organization","role":"controller"}]}`
	good := strings.Replace(bad, `"target_types":["Organization"]`, `"target_types":["URL"]`, 1)
	model := &structuredPlanner{replies: []string{bad, good}}

	// The question names no type an owner controls, so the row type cannot
	// be repaired from it and the retry is needed.
	q, err := Agent{Model: model, Runner: ToolRunner{Graph: graphtest.CampusWebFixture(), Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		Limits: graph.DefaultLimits()}}.CompileQuestion(context.Background(),
		"Please create a table of OWASP Foundation and its hosting providers")
	if err != nil || q.Lens != lens.LensTable || len(model.schemas) != 2 {
		t.Fatalf("q=%+v err=%v calls=%d", q, err, len(model.schemas))
	}

	props := model.schemas[1].Schema["properties"].(map[string]any)
	if enum := props["answer"].(map[string]any)["enum"].([]string); len(enum) != 1 || enum[0] != lens.LensTable {
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
	bad := `{"subject":{"type":"Organization","field":"name","value":"OWASP Foundation"},` +
		`"target_types":["Phone"],"direction":"both","purpose":"connected","relationships":[],"path_rule":"",` +
		`"answer":"controlled","columns":[]}`
	good := strings.Replace(bad, `"answer":"controlled"`, `"answer":"paths"`, 1)
	model := &structuredPlanner{replies: []string{bad, good}}

	if _, err := (Agent{Model: model, Runner: ToolRunner{Graph: graphtest.CampusWebFixture(),
		Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, Limits: graph.DefaultLimits()}}).CompileQuestion(context.Background(),
		"What phone numbers does OWASP list?"); err != nil {
		t.Fatal(err)
	}

	enum := model.schemas[1].Schema["properties"].(map[string]any)["answer"].(map[string]any)["enum"].([]string)
	if len(enum) != len(answerKinds) {
		t.Errorf("controlled retry narrowed the answer kinds: %v", enum)
	}
}

// The schema allows exactly two column shapes, so a schema-enforcing
// provider cannot pair the controller role with a non-organization type.
func TestColumnSchemaAllowsTwoShapes(t *testing.T) {
	props := goalJSONSchema(graphtest.TestOAMCatalog, graphtest.TestOAMCatalog.SearchFields()).Schema["properties"].(map[string]any)
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
