// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func familyQuery(subject PlanSubject) Query {
	q := thirdPartyQuery("", subject, SourceCaller)
	q.Lens = LensFamily
	return q
}

// The family lens answers from a domain without calling the model.
func TestAskFamilyLensFromDomain(t *testing.T) {
	model := &plannerModel{}
	result, err := vendorAgent(model).AskQuery(context.Background(),
		familyQuery(PlanSubject{Type: "FQDN", Field: "name", Value: "colgate.edu"}), AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if model.calls != 0 {
		t.Errorf("the family lens called the model %d time(s)", model.calls)
	}
	if result.FamilyReport == nil || result.FamilyReport.Domain != "colgate.edu" {
		t.Fatalf("missing family report: %+v", result)
	}
	if result.Answer != strings.TrimRight(FormatFamilyReport(*result.FamilyReport), "\n") {
		t.Errorf("answer is not the family report:\n%s", result.Answer)
	}
}

func TestFamilyLensNeedsADomain(t *testing.T) {
	validate := func(q Query) error {
		return ValidateQuery(q, testOAMCatalog.Relations(), testOAMCatalog.SearchFields(), DefaultLimits())
	}
	if err := validate(familyQuery(PlanSubject{Type: "Organization", Name: "Colgate University"})); err == nil {
		t.Error("a family query from an organization was accepted")
	}
	if err := validate(familyQuery(PlanSubject{Type: "FQDN", Field: "name", Value: "colgate.edu"})); err != nil {
		t.Errorf("a family query from a domain was rejected: %v", err)
	}
}

// The family kind is offered to the planner, and a planned family goal
// becomes a family lens query.
func TestPlannerOffersFamilyKind(t *testing.T) {
	k, ok := answerKind(LensFamily)
	if !ok || len(k.Subjects) != 1 || k.Subjects[0] != "FQDN" {
		t.Fatalf("family answer kind = %+v, %v", k, ok)
	}

	raw, err := json.Marshal(goalJSONSchema(testOAMCatalog.Relations(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"`+LensFamily+`"`) {
		t.Error("the goal schema does not offer the family answer")
	}

	goal := InvestigationGoal{Answer: LensFamily, Subject: PlanSubject{Type: "FQDN", Field: "name",
		Value: "jhu.edu"}, Purpose: "connected"}
	q := queryFromPlannedGoal(goal, "Which organizations make up jhu.edu's institution?", testOAMCatalog)
	if q.Lens != LensFamily || q.Subject.Value != "jhu.edu" || !q.Deterministic() {
		t.Errorf("planned family goal became %+v", q)
	}
}

// Asked about a domain, the vendor answer is the full vendors lens: the
// services its TXT records name, checked against the runner's DNS-SD test.
func TestAskVendorsOfDomainUsesVendorsLens(t *testing.T) {
	g := vendorFixture()
	g.evidence = map[string][]Evidence{"colgate.edu": {
		{ID: "t1", SubjectID: "colgate.edu", Kind: "property", Property: map[string]any{
			"property_name": dnsRecordProperty, "header": map[string]any{"rr_type": rrTypeTXT},
			"data": "v=spf1 include:_spf.google.com -all"}},
		{ID: "t2", SubjectID: "colgate.edu", Kind: "property", Property: map[string]any{
			"property_name": dnsRecordProperty, "header": map[string]any{"rr_type": rrTypeTXT},
			"data": "acme-domain-verification=1"}},
		{ID: "t3", SubjectID: "colgate.edu", Kind: "property", Property: map[string]any{
			"property_name": dnsRecordProperty, "header": map[string]any{"rr_type": rrTypeTXT},
			"data": "known-verification=2"}},
	}}

	agent := Agent{Model: &plannerModel{}, Runner: ToolRunner{Graph: g, Catalog: vendorCatalog{testOAMCatalog},
		Limits: DefaultLimits(), KnownVerification: func(r string) bool {
			return strings.HasPrefix(r, "known-verification=")
		}}}
	result, err := agent.AskQuery(context.Background(),
		thirdPartyQuery("", PlanSubject{Type: "FQDN", Field: "name", Value: "colgate.edu"}, SourceCaller),
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"Google Workspace", "acme-domain-verification="} {
		if !strings.Contains(result.Answer, want) {
			t.Errorf("answer lacks %q:\n%s", want, result.Answer)
		}
	}
	if strings.Contains(result.Answer, "known-verification=") {
		t.Errorf("a token the runner knows was reported as unrecognized:\n%s", result.Answer)
	}
}
