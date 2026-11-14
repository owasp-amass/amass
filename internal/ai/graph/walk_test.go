// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/aitest"
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

func TestWalkBoundAndDirection(t *testing.T) {
	l := graph.DefaultLimits()
	l.MaxNodes = 2
	out, err := graph.Walk(context.Background(), aitest.SampleGraph(), l, graph.WalkRequest{StartID: "a", Depth: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Truncated || len(out.Nodes) != 2 {
		t.Fatalf("expected bounded result: %+v", out)
	}

	_, err = graph.Walk(context.Background(), aitest.SampleGraph(), l, graph.WalkRequest{StartID: "a", Depth: 33})
	if err == nil {
		t.Fatal("unbounded depth accepted")
	}

	res, err := graph.Walk(context.Background(), aitest.SampleGraph(), graph.DefaultLimits(),
		graph.WalkRequest{StartID: "c", Direction: "in", Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Nodes) != 3 {
		t.Fatalf("incoming walk: %+v", res)
	}
}

func TestWalkRequiresBoundedReader(t *testing.T) {
	_, err := graph.Walk(context.Background(), aitest.LegacyUnboundedGraph{Graph: aitest.SampleGraph()}, graph.DefaultLimits(),
		graph.WalkRequest{StartID: "a"})
	if err == nil {
		t.Fatal("agent accepted unbounded graph traversal")
	}
}
