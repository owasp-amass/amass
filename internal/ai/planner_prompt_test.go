// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"sort"
	"strings"
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
)

// oamCatalog is the real OAM relationship catalog, built the same way as
// oamrepo.Catalog, with the Asset Database's indexed selector fields.
type oamCatalog struct{}

func (oamCatalog) Relations() []RelationshipSchema {
	var out []RelationshipSchema
	for _, src := range oam.AssetList {
		for _, label := range oam.GetAssetOutgoingRelations(src) {
			for _, rt := range oam.RelationList {
				for _, dst := range oam.GetTransformAssetTypes(src, label, rt) {
					out = append(out, RelationshipSchema{SourceType: string(src), Label: label, RelationType: string(rt), DestinationType: string(dst)})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.SourceType+a.Label+a.RelationType+a.DestinationType < b.SourceType+b.Label+b.RelationType+b.DestinationType
	})
	return out
}

func (oamCatalog) SearchFields() []AssetSearchSchema {
	fields := map[string][]string{
		"Account": {"unique_id", "account_type", "username", "account_number"}, "AutnumRecord": {"number", "handle", "name", "whois_server"},
		"AutonomousSystem": {"number"}, "DomainRecord": {"domain", "name", "extension", "punycode", "id", "whois_server"},
		"File": {"url", "name", "type"}, "FQDN": {"name"}, "FundsTransfer": {"unique_id", "amount", "reference_number"},
		"Identifier": {"unique_id", "id", "id_type"}, "IPAddress": {"address"},
		"IPNetRecord": {"cidr", "handle", "name", "start_address", "end_address", "whois_server", "parent_handle"},
		"Location":    {"address", "city", "country", "postal_code"}, "Netblock": {"cidr"},
		"Organization": {"unique_id", "name", "legal_name", "registration_id", "jurisdiction"},
		"Person":       {"unique_id", "full_name", "first_name", "family_name"}, "Phone": {"e164", "country_code"},
		"Product": {"unique_id", "product_name", "product_type"}, "ProductRelease": {"name"},
		"Service": {"unique_id", "service_type"}, "TLSCertificate": {"serial_number", "subject_common_name"}, "URL": {"url", "scheme"},
	}
	out := make([]AssetSearchSchema, 0, len(fields))
	for t, f := range fields {
		out = append(out, AssetSearchSchema{Type: t, Fields: f})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

func TestQuestionFocus(t *testing.T) {
	rels, sel := oamCatalog{}.Relations(), oamCatalog{}.SearchFields()
	cases := map[string][]string{
		"What is the highest parent organization connected to owasp.org?": {"FQDN", "Organization"},
		"Which IP addresses does https://www.owasp.org/ point to?":        {"IPAddress", "URL"},
		"What netblock contains 192.0.2.10?":                              {"IPAddress", "Netblock"},
		"Who announces 198.51.100.0/24 and AS64500?":                      {"AutonomousSystem", "Netblock"},
	}
	for q, want := range cases {
		f := questionFocus(q, rels, sel)
		for _, typ := range want {
			if !f.Types[typ] {
				t.Errorf("%q: focus lacks %s (got %v)", q, typ, f.Types)
			}
		}
	}
	if f := questionFocus("Which certificates cover owasp.org?", rels, sel); !f.Labels["certificate"] {
		t.Errorf("certificate label not detected: %v", f.Labels)
	}
	// Whole words only: "domains" must not match inside "subdomains" as a label.
	if f := questionFocus("List subdomains of owasp.org", rels, sel); f.Labels["domain"] {
		t.Error("label alias matched inside another word")
	}
}

func TestSlicedPlannerPromptIsMuchSmaller(t *testing.T) {
	rels, sel := oamCatalog{}.Relations(), oamCatalog{}.SearchFields()
	for _, q := range []string{
		"What is the highest parent organization connected to owasp.org?",
		"Which IP addresses does www.owasp.org resolve to?",
		"Tell me about 192.0.2.1",
	} {
		full := goalPlannerPrompt(q, rels, sel, false)
		sliced := goalPlannerPrompt(q, rels, sel, true)
		t.Logf("%-66q full=%5d sliced=%5d chars (%.0f%%)", q, len(full.Text), len(sliced.Text), 100*float64(len(sliced.Text))/float64(len(full.Text)))
		if !sliced.Sliced || len(sliced.Text) > len(full.Text)*55/100 {
			t.Errorf("%q: sliced prompt %d chars is not under 55%% of full %d", q, len(sliced.Text), len(full.Text))
		}
	}
	// A question that names no relationship gets an empty-relationships schema.
	p := goalPlannerPrompt("Tell me about 192.0.2.1", rels, sel, true)
	relSchema := p.Schema.Schema["properties"].(map[string]any)["relationships"].(map[string]any)
	if relSchema["maxItems"] != 0 || !strings.Contains(p.Text, "names no OAM relationship") {
		t.Fatalf("expected an empty relationship slice: %v", relSchema)
	}
	// An explicitly named relationship stays in the slice.
	p = goalPlannerPrompt("Which organizations are connected to owasp.org via website relationships?", rels, sel, true)
	if !p.Explicit || !strings.Contains(p.Text, "|website|") {
		t.Fatal("explicit website relationship missing from the sliced catalog")
	}
}

// replyModel returns the same planner reply on every call.
type replyModel struct {
	reply string
	calls int
}

func (m *replyModel) Generate(context.Context, []Message, []ToolSpec) (Response, error) {
	m.calls++
	return Response{Text: m.reply}, nil
}

// Reproduces a Docker Desktop run: for a parent question that names no
// relationship, qwen3:8b added FQDN --website--> Organization, which OAM
// does not have, and every attempt was rejected.
func TestPlannerDropsRelationshipsTheQuestionDidNotRequest(t *testing.T) {
	bad := `{"subject":{"type":"FQDN","field":"name","value":"owasp.org"},"target_types":["Organization"],"direction":"both","purpose":"ultimate_parent",` +
		`"relationships":[{"source_type":"FQDN","label":"website","relation_type":"SimpleRelation","destination_type":"Organization"}],"path_rule":"all"}`
	model := &replyModel{reply: bad}
	agent := Agent{Model: model, Runner: ToolRunner{Limits: DefaultLimits(), Catalog: oamCatalog{}}}
	q, err := agent.CompileQuestion(context.Background(), "What is the highest parent organization connected to owasp.org?")
	if err != nil {
		t.Fatalf("plan rejected: %v", err)
	}
	if len(q.Relationships) != 0 || q.PathRule != "" || q.Purpose != "ultimate_parent" || model.calls != 1 {
		t.Fatalf("unrequested relationships must be dropped on the first attempt: %+v calls=%d", q, model.calls)
	}

	// "organization" names an asset type here, not the organization relationship.
	p := goalPlannerPrompt("What is the highest parent organization connected to owasp.org?", oamCatalog{}.Relations(), oamCatalog{}.SearchFields(), true)
	if p.NamesRelationship || !strings.Contains(p.Text, "names no OAM relationship") {
		t.Fatal("a type word must not pull its same-named relationship into the slice")
	}

	// When the question does ask for a relationship, an invented transition
	// is still rejected rather than silently dropped.
	model = &replyModel{reply: `{"subject":{"type":"FQDN","field":"name","value":"owasp.org"},"target_types":["TLSCertificate"],"direction":"both","purpose":"connected",` +
		`"relationships":[{"source_type":"FQDN","label":"certificate","relation_type":"SimpleRelation","destination_type":"Organization"}],"path_rule":"any"}`}
	agent.Model = model
	if _, err := agent.CompileQuestion(context.Background(), "Which certificates cover owasp.org?"); err == nil {
		t.Fatal("invented transition accepted for a question that names a relationship")
	}
}
