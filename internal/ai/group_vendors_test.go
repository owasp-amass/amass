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
)

func TestAskGroupVendors(t *testing.T) {
	g := graphtest.GroupVendorFixture()
	reply := `{"subject":{"type":"Organization","field":"name","value":"Colgate University"},"target_types":[],` +
		`"direction":"both","purpose":"connected","relationships":[],"path_rule":"","answer":"group_vendors",` +
		`"columns":[]}`
	model := &plannerModel{replies: []string{reply}}
	agent := Agent{Model: model, Runner: ToolRunner{Graph: g, Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		Limits: graph.DefaultLimits()}}

	res, err := agent.AskAdaptive(context.Background(),
		"Which vendors does Colgate University's corporate group depend on?", AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.GroupVendorReport == nil || !strings.Contains(res.Answer, "EDUCAUSE: used by 2 of 3") {
		t.Fatalf("answer:\n%s", res.Answer)
	}
}
