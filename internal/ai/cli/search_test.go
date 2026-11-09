// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

type cliTestGraph struct{}

func (cliTestGraph) GetAsset(_ context.Context, id string) (ai.Asset, error) {
	if id == "1" {
		return ai.Asset{ID: "1", Type: "FQDN", Key: "tech.acme.example"}, nil
	}

	return ai.Asset{ID: "2", Type: "Organization", Key: "Acme Holdings"}, nil
}

func (cliTestGraph) FindAssets(context.Context, string, time.Time, int) ([]ai.Asset, error) {
	return nil, nil
}

func (cliTestGraph) Edges(context.Context, string, string, string, time.Time) ([]ai.Relation, error) {
	return nil, nil
}

func (cliTestGraph) Evidence(context.Context, string, int) ([]ai.Evidence, error) { return nil, nil }

func (cliTestGraph) EdgesLimited(_ context.Context, id, dir, label string, _ time.Time, limit int) ([]ai.Relation, bool, error) {
	if id == "1" {
		return []ai.Relation{{ID: "e1", FromID: "2", ToID: "1", Label: "domain", Type: "SimpleRelation"}}, false, nil
	}

	return []ai.Relation{}, false, nil
}

type cliTestCatalog struct{}

func (cliTestCatalog) Relations() []ai.RelationshipSchema {
	return []ai.RelationshipSchema{
		{SourceType: "Organization", Label: "domain", RelationType: "SimpleRelation", DestinationType: "FQDN"},
	}
}

func TestGraphSearchUserFacingTextAndMermaid(t *testing.T) {
	runner := ai.ToolRunner{Graph: cliTestGraph{}, Catalog: cliTestCatalog{}, Limits: ai.DefaultLimits()}
	for _, format := range []string{"text", "mermaid", "json"} {
		var buf bytes.Buffer
		err := graphSearch(context.Background(), runner, graphSearchOptions{
			SubjectID: "1", TargetTypes: "Organization", MaxDepth: 3, Format: format,
		}, &buf)
		if err != nil {
			t.Fatal(err)
		}

		output := buf.String()
		switch format {
		case "text":
			if !strings.Contains(output, "depth=1") || !strings.Contains(output,
				"<--domain") || !strings.Contains(output, "Acme Holdings") {
				t.Fatalf("wrong text: %s", output)
			}
		case "mermaid":
			if !strings.Contains(output, "flowchart LR") || !strings.Contains(output, "domain") {
				t.Fatalf("wrong Mermaid: %s", output)
			}
		case "json":
			var data graphSearchResponse
			if err := json.Unmarshal(buf.Bytes(), &data); err != nil {
				t.Fatal(err)
			}
			if data.Status != "matched" || data.Search == nil || len(data.Search.Matches) != 1 {
				t.Fatalf("wrong JSON: %+v", data)
			}
		}
	}
}

func TestGraphSearchRejectsAmbiguousSelectors(t *testing.T) {
	runner := ai.ToolRunner{Graph: cliTestGraph{}, Catalog: cliTestCatalog{}, Limits: ai.DefaultLimits()}
	cases := []graphSearchOptions{
		{Format: "json", SubjectType: "FQDN", SubjectField: "name"},
		{Format: "json", SubjectID: "1", SubjectValue: "other"},
		{Format: "xml", SubjectID: "1"},
		{Format: "json", SubjectID: "1", TargetTypes: "UnknownAssetType"},
	}
	for _, tc := range cases {
		if err := graphSearch(context.Background(), runner, tc, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe search request accepted: %+v", tc)
		}
	}
}

func TestCollectionRequiresExactApprovalBeforeNetwork(t *testing.T) {
	p := ai.PlanCollection(ai.AssetSelector{Type: "FQDN", Field: "name", Value: "example.org"})
	var out bytes.Buffer
	if err := collectTarget(context.Background(), nil, p, "", false, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"approval_required"`) {
		t.Fatalf("missing approval proposal: %s", out.String())
	}
	for _, approval := range []string{"", "wrong-approval"} {
		if err := collectTarget(context.Background(), nil, p, approval, true, &bytes.Buffer{}); err == nil {
			t.Fatal("collection started without matching approval")
		}
	}
}
