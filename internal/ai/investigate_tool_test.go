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

func investigate(t *testing.T, store *EvidenceStore, args string) map[string]any {
	t.Helper()

	g, cat := campusWeb()
	raw, err := RunInvestigationTool(context.Background(), ToolRunner{Graph: g, Catalog: cat, Limits: DefaultLimits()},
		nil, store, ToolInvestigate, json.RawMessage(args))
	if err != nil {
		t.Fatal(err)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}

	return out
}

func verify(t *testing.T, store *EvidenceStore, id, text string) (map[string]any, error) {
	t.Helper()

	args, _ := json.Marshal(map[string]string{"investigation_id": id, "text": text})
	raw, err := RunInvestigationTool(context.Background(), ToolRunner{}, nil, store, ToolVerifyCitations, args)
	if err != nil {
		return nil, err
	}

	var out map[string]any
	return out, json.Unmarshal(raw, &out)
}

// An MCP client asks for colgate.edu's vendors, then has its own summary
// checked against the evidence.
func TestInvestigateThenVerifyCitations(t *testing.T) {
	store := NewEvidenceStore()
	out := investigate(t, store,
		`{"subject":{"type":"FQDN","field":"name","value":"colgate.edu"},"answer":"third_party"}`)
	if out["answer_kind"] != LensThirdParty || len(out["evidence"].([]any)) == 0 {
		t.Fatalf("unexpected result: %v", out)
	}

	id := out["investigation_id"].(string)
	res, err := verify(t, store, id, "www.colgate.edu resolves to 151.101.1.1 [E6].")
	if err != nil || res["verified"] != true {
		t.Fatalf("grounded prose not verified: %v %v", res, err)
	}

	res, err = verify(t, store, id, "colgate.edu is hosted by www.cloudflare.com [E1].")
	if err != nil || res["verified"] != false || len(res["problems"].([]any)) == 0 {
		t.Fatalf("ungrounded prose verified: %v %v", res, err)
	}
	if _, err := verify(t, store, "inv-unknown", "x [E1]."); err == nil {
		t.Fatal("unknown investigation_id accepted")
	}
}

func TestInvestigateTable(t *testing.T) {
	out := investigate(t, NewEvidenceStore(), `{"subject":{"type":"Organization","name":"Colgate University"},`+
		`"answer":"table","target_types":["URL"],"columns":[{"type":"IPAddress","role":""},`+
		`{"type":"Organization","role":"controller"}]}`)
	rows := out["rows"].([]any)
	if len(rows) != 2 || !strings.Contains(out["answer"].(string),
		"| https://www.colgate.edu | 151.101.1.1 | FASTLY |") {
		t.Fatalf("table not returned: %v", out)
	}
}

func TestInvestigateRejectsBadRequests(t *testing.T) {
	g, cat := campusWeb()
	runner := ToolRunner{Graph: g, Catalog: cat, Limits: DefaultLimits()}
	for args, want := range map[string]string{
		`{"subject":{"type":"FQDN","field":"name","value":"colgate.edu"},"answer":"paths","target_types":["Organization"]}`: "needs a model",
		`{"subject":{"type":"Organization","name":"Colgate University"},"answer":"table","target_types":["Phone"],` +
			`"columns":[{"type":"Organization","role":"controller"}]}`: "cannot be a row",
		`{"subject":{"type":"FQDN","field":"name","value":"colgate.edu"},"answer":"route"}`:                 "needs hops",
		`{"subject":{"type":"FQDN","field":"name","value":"colgate.edu"},"answer":"guess"}`:                 "unknown answer",
		`{"subject":{"type":"FQDN","field":"name","value":"colgate.edu"},"answer":"third_party","extra":1}`: "unknown field",
	} {
		_, err := RunInvestigationTool(context.Background(), runner, nil, NewEvidenceStore(), ToolInvestigate,
			json.RawMessage(args))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err=%v, want %q", args, err, want)
		}
	}
}

func TestInvestigationSpecsEnumerateAnswerKinds(t *testing.T) {
	specs := InvestigationSpecs(vendorCatalog{testOAMCatalog})
	if len(specs) != 2 || specs[0].Name != ToolInvestigate {
		t.Fatalf("specs = %+v", specs)
	}

	enum := specs[0].Parameters["properties"].(map[string]any)["answer"].(map[string]any)["enum"].([]string)
	if !strings.Contains(strings.Join(enum, ","), "table") || !strings.Contains(strings.Join(enum, ","), "route") {
		t.Errorf("answer enum = %v", enum)
	}
	if !strings.Contains(specs[0].Description, "Types an owner can control:") {
		t.Error("investigate description lacks controllable types")
	}
}

func TestEvidenceStoreIsBounded(t *testing.T) {
	s := NewEvidenceStore()
	first, _ := s.put(EvidenceBundle{})
	for i := 0; i < evidenceStoreEntries; i++ {
		_, _ = s.put(EvidenceBundle{})
	}
	if _, ok := s.get(first); ok {
		t.Error("oldest investigation was not evicted")
	}
}
