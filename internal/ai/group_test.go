// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/aitest"
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

// The planner's group answer runs the lens without another model call.
func TestAskCorporateGroup(t *testing.T) {
	g := aitest.GroupFixture()
	reply := `{"subject":{"type":"Organization","field":"name","value":"Spotify USA Inc."},"target_types":[],` +
		`"direction":"both","purpose":"connected","relationships":[],"path_rule":"","answer":"org_group","columns":[]}`
	model := &plannerModel{replies: []string{reply}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: g, Catalog: aitest.VendorCatalog{PlanCatalog: aitest.TestOAMCatalog},
		Limits: graph.DefaultLimits()}}

	res, err := agent.AskAdaptive(context.Background(), "Who owns Spotify USA Inc.?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OrgGroupReport == nil || model.calls != 1 || !strings.Contains(res.Answer, "Ultimate parent: Spotify Technology") {
		t.Fatalf("calls %d, answer:\n%s", model.calls, res.Answer)
	}
}
