// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// A question about exposed services is planned as the services answer and
// answered by the lens, with the identified software in the answer.
func TestAskServices(t *testing.T) {
	g := graphtest.ServicesFixture()
	reply := `{"subject":{"type":"FQDN","field":"name","value":"owasp.org"},"target_types":[],` +
		`"direction":"both","purpose":"connected","relationships":[],"path_rule":"","answer":"services","columns":[]}`
	model := &plannerModel{replies: []string{reply}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: g, Catalog: graphtest.VendorCatalog{
		PlanCatalog: graphtest.TestOAMCatalog,
	},
		Limits: graph.DefaultLimits()}}

	res, err := agent.AskAdaptive(context.Background(), "What services does owasp.org expose?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !isReport[lens.ServicesReport](res.LensReport) || model.calls != 1 || !strings.Contains(res.Answer,
		"runs nginx 1.18.0") {
		t.Fatalf("calls %d, answer:\n%s", model.calls, res.Answer)
	}

	raw, err := json.Marshal(goalJSONSchema(graphtest.TestOAMCatalog.Relations(), nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{
		lens.LensServices,
		lens.LensGroupVendors,
		lens.LensNetwork,
		lens.LensDangling,
		lens.LensChanges,
	} {
		if !strings.Contains(string(raw), `"`+kind+`"`) {
			t.Errorf("the goal schema does not offer the %s answer", kind)
		}
	}
}

// A question about network infrastructure is planned as the network answer
// and answered by the lens.
func TestAskNetwork(t *testing.T) {
	g := graphtest.VendorFixture()
	reply := `{"subject":{"type":"FQDN","field":"name","value":"owasp.org"},"target_types":[],` +
		`"direction":"both","purpose":"connected","relationships":[],"path_rule":"","answer":"network","columns":[]}`
	model := &plannerModel{replies: []string{reply}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: g, Catalog: graphtest.VendorCatalog{
		PlanCatalog: graphtest.TestOAMCatalog,
	},
		Limits: graph.DefaultLimits()}}

	res, err := agent.AskAdaptive(context.Background(), "Which IP ranges belong to owasp.org?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !isReport[lens.NetworkReport](res.LensReport) || model.calls != 1 || !strings.Contains(res.Answer,
		"203.0.113.0/24") ||
		!strings.Contains(res.Answer, "FASTLY") {
		t.Fatalf("calls %d, answer:\n%s", model.calls, res.Answer)
	}
}

// A question about dangling DNS is planned as the dangling_dns answer and
// answered by the lens.
func TestAskDanglingDNS(t *testing.T) {
	g := graphtest.VendorFixture()
	reply := `{"subject":{"type":"FQDN","field":"name","value":"owasp.org"},"target_types":[],` +
		`"direction":"both","purpose":"connected","relationships":[],"path_rule":"","answer":"dangling_dns","columns":[]}`
	model := &plannerModel{replies: []string{reply}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: g, Catalog: graphtest.VendorCatalog{
		PlanCatalog: graphtest.TestOAMCatalog,
	},
		Limits: graph.DefaultLimits()}}

	res, err := agent.AskAdaptive(context.Background(), "Could any owasp.org subdomain be taken over?",
		AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !isReport[lens.DanglingReport](res.LensReport) || model.calls != 1 || !strings.Contains(res.Answer,
		"Dangling DNS of owasp.org") {
		t.Fatalf("calls %d, answer:\n%s", model.calls, res.Answer)
	}
}

// A question about recent changes is planned as the changes answer and
// answered by the lens over the default window.
func TestAskChanges(t *testing.T) {
	g := graphtest.VendorFixture()
	reply := `{"subject":{"type":"FQDN","field":"name","value":"owasp.org"},"target_types":[],` +
		`"direction":"both","purpose":"connected","relationships":[],"path_rule":"","answer":"changes","columns":[]}`
	model := &plannerModel{replies: []string{reply}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: g, Catalog: graphtest.VendorCatalog{
		PlanCatalog: graphtest.TestOAMCatalog,
	},
		Limits: graph.DefaultLimits()}}

	res, err := agent.AskAdaptive(context.Background(), "What changed recently for owasp.org?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !isReport[lens.ChangesReport](res.LensReport) || model.calls != 1 || !strings.Contains(res.Answer,
		"Changes to owasp.org and OWASP Foundation since") {
		t.Fatalf("calls %d, answer:\n%s", model.calls, res.Answer)
	}
}

// Every registered subject lens is an answer kind the planner can choose,
// answered through the registry.
func TestAskRegisteredLenses(t *testing.T) {
	for _, l := range lens.SubjectLenses() {
		if l.NeedsOther {
			if _, ok := answerKind(l.Name); ok {
				t.Errorf("%s needs a second subject but is an answer kind", l.Name)
			}

			continue
		}

		g := graphtest.VendorFixture()
		reply := `{"subject":{"type":"FQDN","field":"name","value":"owasp.org"},"target_types":[],` +
			`"direction":"both","purpose":"connected","relationships":[],"path_rule":"","answer":"` + l.Name +
			`","columns":[]}`
		model := &plannerModel{replies: []string{reply}}
		agent := Agent{Model: model, Runner: ToolRunner{Graph: g,
			Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, Limits: graph.DefaultLimits()}}

		res, err := agent.AskAdaptive(context.Background(), "Tell me about owasp.org's "+l.Name, AdaptiveOptions{})
		if err != nil {
			t.Fatalf("%s: %v", l.Name, err)
		}
		if res.LensReport == nil || model.calls != 1 || res.Answer == "" {
			t.Errorf("%s: calls %d, answer:\n%s", l.Name, model.calls, res.Answer)
		}
	}
}

// isReport reports whether an investigation's lens report has type T.
func isReport[T lens.Report](r lens.Report) bool {
	_, ok := r.(T)
	return ok
}
