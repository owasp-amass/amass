// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/aitest"
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
	"github.com/owasp-amass/amass/v5/internal/ai/lens"
)

// A question about exposed services is planned as the services answer and
// answered by the lens, with the identified software in the answer.
func TestAskServices(t *testing.T) {
	g := aitest.ServicesFixture()
	reply := `{"subject":{"type":"FQDN","field":"name","value":"colgate.edu"},"target_types":[],` +
		`"direction":"both","purpose":"connected","relationships":[],"path_rule":"","answer":"services","columns":[]}`
	model := &plannerModel{replies: []string{reply}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: g, Catalog: aitest.VendorCatalog{PlanCatalog: aitest.TestOAMCatalog},
		Limits: graph.DefaultLimits()}}

	res, err := agent.AskAdaptive(context.Background(), "What services does colgate.edu expose?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ServicesReport == nil || model.calls != 1 || !strings.Contains(res.Answer, "runs nginx 1.18.0") {
		t.Fatalf("calls %d, answer:\n%s", model.calls, res.Answer)
	}

	raw, err := json.Marshal(goalJSONSchema(aitest.TestOAMCatalog.Relations(), nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{lens.LensServices, lens.LensGroupVendors} {
		if !strings.Contains(string(raw), `"`+kind+`"`) {
			t.Errorf("the goal schema does not offer the %s answer", kind)
		}
	}
}
