// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// Investigation tools let an MCP client, which is itself the model, use the
// answer kinds directly: investigate runs a structured question and returns
// the computed answer with numbered evidence, and verify_citations checks
// the client's prose against that evidence. Every answer kind except paths
// runs without a model on the Amass side.
const (
	ToolInvestigate      = "investigate"
	ToolVerifyCitations  = "verify_citations"
	investigateTimeout   = 2 * time.Minute
	investigateMaxItems  = 200
	investigateMaxRows   = 200
	evidenceStoreEntries = 64
)

// EvidenceStore keeps the evidence of recent investigations so that a
// client can have its prose verified later. It is bounded and in memory.
type EvidenceStore struct {
	mu      sync.Mutex
	bundles map[string]review.EvidenceBundle
	order   []string
}

// NewEvidenceStore returns an empty store.
func NewEvidenceStore() *EvidenceStore {
	return &EvidenceStore{bundles: map[string]review.EvidenceBundle{}}
}

func (s *EvidenceStore) put(b review.EvidenceBundle) (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	id := "inv-" + hex.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.bundles[id] = b
	s.order = append(s.order, id)
	for len(s.order) > evidenceStoreEntries {
		delete(s.bundles, s.order[0])
		s.order = s.order[1:]
	}

	return id, nil
}

func (s *EvidenceStore) get(id string) (review.EvidenceBundle, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.bundles[id]
	return b, ok
}

// IsInvestigationTool reports whether name is served by RunInvestigationTool.
func IsInvestigationTool(name string) bool {
	return name == ToolInvestigate || name == ToolVerifyCitations
}

// ToolTimeout is the time a tool call may take.
func ToolTimeout(name string) time.Duration {
	if name == ToolInvestigate {
		return investigateTimeout
	}

	return 25 * time.Second
}

// InvestigationSpecs describes the investigation tools, with enums
// generated from the catalog, the answer kinds and the semantics table.
func InvestigationSpecs(schema graph.SchemaCatalog) []llm.ToolSpec {
	if schema == nil {
		return nil
	}

	var selectors []graph.AssetSearchSchema
	if sc, ok := schema.(graph.AssetSearchCatalog); ok {
		selectors = sc.SearchFields()
	}

	goal := goalJSONSchema(schema.Relations(), selectors).Schema["properties"].(map[string]any)
	kinds := append(answerKindNames(), TraversalRoute)
	hop := llm.ObjectSchema([]string{"direction", "label", "relation_type", "destination_type"}, map[string]any{
		"direction":        map[string]any{"type": "string", "enum": []string{"out", "in"}},
		"label":            llm.StringProp("Exact OAM relation label"),
		"relation_type":    llm.StringProp("Exact OAM relation type, e.g. SimpleRelation"),
		"destination_type": llm.StringProp("OAM asset type reached by the hop"),
	})

	var kindText strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(answerKindCatalog(lens.OwnedTypes(schema), false)), "\n") {
		kindText.WriteString(line + "\n")
	}

	return []llm.ToolSpec{
		{
			Name: ToolInvestigate,
			Description: "Answer a structured question from the Amass Asset Database and return the computed answer " +
				"with numbered evidence (E1, E2, ...) to cite. Choose answer:\n" + kindText.String() +
				"- route (target_types: the last hop's type): follow exactly the listed hops from the subject.\n" +
				"The paths answer needs a model configured on the Amass side; the others do not.",
			Parameters: llm.ObjectSchema([]string{"subject", "answer"}, map[string]any{
				"subject":      goal["subject"],
				"answer":       map[string]any{"type": "string", "enum": kinds},
				"target_types": goal["target_types"],
				"columns":      goal["columns"],
				"purpose":      goal["purpose"],
				"hops":         map[string]any{"type": "array", "items": hop, "maxItems": 3},
			}),
		},
		{
			Name: ToolVerifyCitations,
			Description: "Check prose against the evidence of an earlier investigate call: every sentence must cite " +
				"evidence items like [E1], every cited item must exist, assets named in a sentence must appear in " +
				"its cited items, and hostnames or IP addresses must come from the evidence.",
			Parameters: llm.ObjectSchema([]string{"investigation_id", "text"}, map[string]any{
				"investigation_id": llm.StringProp("The investigation_id returned by investigate"),
				"text":             llm.StringProp("The prose to verify"),
			}),
		},
	}
}

type investigateArgs struct {
	Subject     PlanSubject        `json:"subject"`
	Answer      string             `json:"answer"`
	TargetTypes []string           `json:"target_types"`
	Columns     []lens.TableColumn `json:"columns"`
	Purpose     string             `json:"purpose"`
	Hops        []PlanHop          `json:"hops"`
}

// queryFromArgs builds and validates the Query an investigate call asks
// for.
func queryFromArgs(a investigateArgs, schema graph.SchemaCatalog) (Query, error) {
	var selectors []graph.AssetSearchSchema
	if sc, ok := schema.(graph.AssetSearchCatalog); ok {
		selectors = sc.SearchFields()
	}

	a.Subject = organizationSubject(normalizePlannedSubject(a.Subject, selectors))
	if a.Answer == TraversalRoute {
		if len(a.Hops) == 0 {
			return Query{}, errors.New("a route needs hops")
		}

		return Query{Version: QueryVersion, Subject: a.Subject, Traversal: TraversalRoute,
			TargetTypes: []string{a.Hops[len(a.Hops)-1].DestinationType}, Direction: "both", Purpose: "connected",
			Hops: a.Hops, Source: SourceCaller}, nil
	}
	if len(a.Hops) != 0 {
		return Query{}, errors.New("hops apply only to answer route")
	}

	purpose := a.Purpose
	if purpose == "" {
		purpose = "connected"
	}

	direction := "both"
	if a.Answer == AnswerHierarchy {
		direction = "out"
	}

	goal := InvestigationGoal{Subject: a.Subject, TargetTypes: a.TargetTypes, Direction: direction, Purpose: purpose,
		Answer: a.Answer, Columns: a.Columns}
	if err := validateGoal(goal, schema.Relations(), selectors); err != nil {
		return Query{}, err
	}
	if err := validateAnswer(goal, schema); err != nil {
		return Query{}, err
	}

	q := queryFromPlannedGoal(goal, "", schema)
	q.Source = SourceCaller
	return q, nil
}

// RunInvestigationTool serves investigate and verify_citations. model may
// be nil; the paths answer then fails with advice to choose another kind.
func RunInvestigationTool(ctx context.Context, runner ToolRunner, model llm.Model, store *EvidenceStore, name string, args json.RawMessage) (json.RawMessage, error) {
	if store == nil {
		return nil, errors.New("evidence store not configured")
	}
	switch name {
	case ToolInvestigate:
		var a investigateArgs
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, fmt.Errorf("invalid investigate arguments: %w", err)
		}
		if runner.Catalog == nil {
			return nil, errors.New("OAM catalog not configured")
		}

		q, err := queryFromArgs(a, runner.Catalog)
		if err != nil {
			return nil, err
		}
		if model == nil && !q.Deterministic() {
			return nil, errors.New("the paths answer needs a model on the Amass side; choose hierarchy, " +
				"controlled, third_party, table or route")
		}

		inv, err := (Agent{Model: model, Runner: runner}).AskQuery(ctx, q, AdaptiveOptions{})
		if err != nil {
			return nil, err
		}

		bundle := BuildEvidenceBundle(inv, investigateMaxItems)
		id, err := store.put(bundle)
		if err != nil {
			return nil, err
		}

		return json.Marshal(investigateResult(id, q, inv, bundle))
	case ToolVerifyCitations:
		var a struct {
			InvestigationID string `json:"investigation_id"`
			Text            string `json:"text"`
		}
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, fmt.Errorf("invalid verify_citations arguments: %w", err)
		}

		bundle, ok := store.get(a.InvestigationID)
		if !ok {
			return nil, errors.New("unknown or expired investigation_id; run investigate again")
		}

		problems := VerifyCitations(a.Text, bundle)
		cited := []string{}
		for _, i := range CitedItems(a.Text, bundle) {
			cited = append(cited, i.Line())
		}

		return json.Marshal(map[string]any{"verified": len(problems) == 0, "problems": problems, "cited": cited})
	}

	return nil, fmt.Errorf("unknown investigation tool %q", name)
}

// investigateResult is the client-facing summary of an investigation.
func investigateResult(id string, q Query, inv Investigation, b review.EvidenceBundle) map[string]any {
	evidence := make([]string, 0, len(b.Items))
	for _, i := range b.Items {
		evidence = append(evidence, i.Line())
	}

	answer := inv.Answer
	if len(answer) > 20000 {
		answer = answer[:20000] + "\n[answer truncated; see the structured result]"
	}

	out := map[string]any{
		"investigation_id":   id,
		"query":              q.Describe(),
		"answer_kind":        answerKindOf(&q),
		"answer":             answer,
		"incomplete":         inv.Incomplete,
		"evidence":           evidence,
		"evidence_truncated": b.Truncated,
	}
	if r := inv.ThirdPartyReport; r != nil {
		vendors := make([]lens.VendorUse, 0, len(r.Vendors))
		for _, v := range r.Vendors {
			v.Witness = nil // the evidence list carries the edges
			vendors = append(vendors, v)
		}

		out["vendors"] = vendors
	}
	if r := inv.FamilyReport; r != nil {
		members := make([]map[string]any, 0, len(r.Members))
		for _, m := range r.Members {
			members = append(members, map[string]any{"organization": graph.AssetLabel(m.Organization),
				"relation": m.Relation, "evidence": m.Evidence})
		}

		family := map[string]any{"members": members, "related_domains": r.RelatedDomains}
		if r.Main != nil {
			family["main"] = graph.AssetLabel(*r.Main)
		}
		out["family"] = family
	}
	if r := inv.OrgGroupReport; r != nil {
		members := make([]map[string]any, 0, len(r.Members))
		for _, m := range r.Members {
			members = append(members, map[string]any{"organization": graph.AssetLabel(m.Organization),
				"parent_id": m.ParentID, "relationship": m.Label, "depth": m.Depth,
				"jurisdiction": m.Jurisdiction, "registration_id": m.RegistrationID})
		}
		out["org_group"] = members
	}
	if r := inv.ServicesReport; r != nil {
		services := make([]map[string]any, 0, len(r.Services))
		for i, s := range r.Services {
			if i == investigateMaxRows {
				out["services_truncated"] = true
				break
			}
			services = append(services, map[string]any{"type": s.ServiceType, "endpoints": s.Endpoints,
				"ports": s.Ports, "software": s.Software, "identified": s.Identified, "certificates": s.Certificates,
				"unusual_ports": s.UnusualPorts})
		}
		out["services"], out["services_by_product"] = services, r.ByProduct
	}
	if r := inv.GroupVendorReport; r != nil {
		out["group_vendors"], out["group_internal"] = r.Vendors, r.Internal
	}
	if r := inv.LensReport; r != nil {
		out["lens_report"] = r
	}
	if r := inv.ChangesReport; r != nil {
		out["changes_since"] = r.Since
		out["new_assets"], out["new_relations"] = r.NewAssets, r.NewRelations
		out["quiet_assets"], out["quiet_relations"] = r.QuietAssets, r.QuietRelations
	}
	if r := inv.DanglingReport; r != nil {
		out["dangling_dns"] = r.Findings
	}
	if r := inv.NetworkReport; r != nil {
		out["networks"], out["autonomous_systems"], out["hosting"] = r.Networks, r.ASNs, r.Hosting
		out["unused_networks"], out["unresolved_names"] = r.Unused, r.Unresolved
		out["foreign_names"] = r.Foreign
	}
	if r := inv.TableReport; r != nil {
		rows := r.Rows
		if len(rows) > investigateMaxRows {
			rows, out["rows_truncated"] = rows[:investigateMaxRows], true
		}

		out["headers"], out["rows"] = r.Headers, rows
	}

	return out
}
