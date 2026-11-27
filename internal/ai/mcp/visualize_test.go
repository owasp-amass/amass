// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// namedGraph adds name lookups to a fixture.
type namedGraph struct{ graphtest.VendorGraph }

func (g namedGraph) ResolveAsset(_ context.Context, s graph.AssetSelector, _ int) (graph.AssetResolution, error) {
	out := graph.AssetResolution{Query: s, Status: "not_found"}
	for _, a := range g.Assets {
		if a.Type == s.Type && a.Key == s.Value {
			out.Status = "found"
			out.Candidates = append(out.Candidates, graph.OrganizationCandidate{Asset: a})
		}
	}

	return out, nil
}

func TestVisualizeDrawsAndLinks(t *testing.T) {
	runner := ai.ToolRunner{Graph: namedGraph{graphtest.ServicesFixture()}, Limits: graph.DefaultLimits(),
		Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}}
	svc := NewHTTPServer(runner, readerToken)
	var handler http.Handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	svc.Viz = &VizLinks{BaseURL: server.URL, Runner: runner}
	handler = svc.Handler()

	cs := connect(t, server.URL, readerToken, nil)
	text, isErr := call(t, cs, ToolVisualize, map[string]any{"subject": "OWASP.org"})
	if isErr {
		t.Fatal(text)
	}

	var out struct {
		Mermaid, MermaidDetail string
		Assets                 int
		URL                    string `json:"interactive_url"`
		GEXF                   string `json:"gexf_url"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	if out.Assets < 3 || !strings.HasPrefix(out.Mermaid, "flowchart LR") || !strings.HasPrefix(out.URL, server.URL) {
		t.Fatalf("visualize = %s", text)
	}

	for _, link := range []string{out.URL, out.GEXF} {
		resp, err := http.Get(link)
		if err != nil {
			t.Fatal(err)
		}

		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), "owasp.org") {
			t.Errorf("%s = %d", link, resp.StatusCode)
		}
	}
	if resp, err := http.Get(server.URL + vizLinkPrefix + "nope"); err != nil || resp.StatusCode != 404 {
		t.Errorf("an unknown link was served")
	}

	if text, isErr := call(t, cs, ToolVisualize, map[string]any{"subject": "missing.example"}); !isErr ||
		!strings.Contains(text, "not in the database") {
		t.Errorf("missing subject: %s", text)
	}
}
