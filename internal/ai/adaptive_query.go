// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// AskQuery validates and executes a structured Query, such as one supplied
// by a CLI or MCP caller. Route and hierarchy queries need no model; explore
// queries use the model to guide search and choose among witnessed paths.
func (a Agent) AskQuery(ctx context.Context, q Query, opts AdaptiveOptions) (out Investigation, err error) {
	a, meter := a.metered()
	defer func() {
		if meter != nil {
			out.Usage = meter.Snapshot()
		}
	}()
	if a.Runner.Graph == nil || a.Runner.Catalog == nil {
		return out, errors.New("graph and OAM catalog required")
	}
	if a.Model == nil && !q.Deterministic() {
		return out, errors.New("a model is required for explore queries")
	}

	q.Subject = organizationSubject(q.Subject)
	if err := a.Runner.Limits.Validate(); err != nil {
		return out, err
	}

	var selectors []graph.AssetSearchSchema
	if c, ok := a.Runner.Catalog.(graph.AssetSearchCatalog); ok {
		selectors = c.SearchFields()
	}
	if err := ValidateQuery(q, a.Runner.Catalog.Relations(), selectors, a.Runner.Limits); err != nil {
		out.Incomplete = true
		return out, fmt.Errorf("invalid query: %w", err)
	}

	return a.executeQuery(ctx, q, opts, out)
}

// executeQuery runs a validated Query: resolve the root exactly, search,
// inspect source evidence, select paths and render the answer.
func (a Agent) executeQuery(ctx context.Context, q Query, opts AdaptiveOptions, out Investigation) (Investigation, error) {
	out.Query = &q
	goal := q.Goal()
	question := q.Question
	if strings.TrimSpace(question) == "" {
		question = q.Describe()
	}

	fqdnInventory := q.Traversal == TraversalHierarchy
	typedRelation := q.Traversal == TraversalRoute
	typedIntent := TypedRelationIntent{Goal: goal, Hops: q.Hops}
	out.Goal = &goal
	resolveStarted := time.Now()
	var root graph.Asset
	if goal.Subject.UsesOrganizationResolution() {
		args, _ := json.Marshal(struct {
			graph.OrganizationQuery
			Limit int `json:"limit"`
		}{OrganizationQuery: goal.Subject.OrganizationQuery(), Limit: 10})
		raw, err := a.Runner.Run(ctx, "resolve_organization", args)
		if err != nil {
			out.Incomplete = true
			return out, err
		}

		out.ToolCalls++
		out.Observations = append(out.Observations,
			Observation{Tool: "resolve_organization", CallID: "adaptive-root", Result: string(raw)})
		var resolution graph.OrganizationResolution
		if err := json.Unmarshal(raw, &resolution); err != nil {
			out.Incomplete = true
			return out, err
		}

		out.Resolution = &resolution
		if resolution.Status != "matched" || len(resolution.Candidates) != 1 {
			out.Incomplete = true
			answer := resolutionAnswer(resolution.Status, resolution.Candidates) + " Searched for " +
				formatPlanSubject(goal.Subject) + "."
			// A misspelled or partial name resolves to nothing; offer the
			// closest stored organizations so the user can pick the one meant.
			if resolution.Status == "not_found" && goal.Subject.Name != "" {
				if sg, ok := a.Runner.Graph.(graph.OrgSearchGraph); ok {
					if s, serr := graph.ResolveOrSuggest(ctx, sg, goal.Subject.Name, 5); serr == nil &&
						s.Status == graph.StatusSuggestions && len(s.Candidates) > 0 {
						answer += " Did you mean: " + orgSuggestionText(s.Candidates) +
							"? Re-run with the exact name."
					}
				}
			}
			out.Answer = answer
			out.recordTrace(resolveStarted, InvestigationTraceEvent{Stage: "resolve_asset", Incomplete: true,
				Detail: resolution.Status + " " + formatPlanSubject(goal.Subject)})
			return out, nil
		}

		root = resolution.Candidates[0].Asset
	} else {
		args, _ := json.Marshal(struct {
			graph.AssetSelector
			Limit int `json:"limit"`
		}{AssetSelector: goal.Subject.AssetSelector(), Limit: 10})
		raw, err := a.Runner.Run(ctx, "resolve_asset", args)
		if err != nil {
			out.Incomplete = true
			return out, err
		}

		out.ToolCalls++
		out.Observations = append(out.Observations,
			Observation{Tool: "resolve_asset", CallID: "adaptive-root", Result: string(raw)})
		var resolution graph.AssetResolution
		if err := json.Unmarshal(raw, &resolution); err != nil {
			out.Incomplete = true
			return out, err
		}

		out.AssetResolution = &resolution
		if resolution.Status != "matched" || len(resolution.Candidates) != 1 {
			out.Incomplete = true
			out.Answer = resolutionAnswer(resolution.Status, resolution.Candidates) + " Searched for " +
				formatPlanSubject(goal.Subject) + "."
			out.recordTrace(resolveStarted, InvestigationTraceEvent{Stage: "resolve_asset", Incomplete: true,
				Detail: resolution.Status + " " + formatPlanSubject(goal.Subject)})
			if resolution.Status == "not_found" {
				proposal := PlanCollection(goal.Subject.AssetSelector())
				out.Collection = &proposal
			}

			return out, nil
		}

		root = resolution.Candidates[0].Asset
	}

	out.recordTrace(resolveStarted, InvestigationTraceEvent{Stage: "resolve_asset", Detail: root.Type})
	switch q.Lens {
	case lens.LensThirdParty:
		return a.thirdPartyLens(ctx, root, out)
	case lens.LensControlled:
		return a.controlledLens(ctx, root, q.TargetTypes, opts, out)
	case lens.LensTable:
		return a.tableLens(ctx, root, q, opts, out)
	case lens.LensOwnershipGaps:
		return a.gapLens(ctx, root, out)
	case LensFamily:
		return a.familyLens(ctx, root, out)
	case lens.LensOrgGroup:
		return a.orgGroupLens(ctx, root, out)
	case lens.LensGroupVendors:
		return a.groupVendorsLens(ctx, root, out)
	}
	if l, ok := lens.SubjectLensNamed(q.Lens); ok && !l.NeedsOther {
		return a.reportLens(ctx, l, root, out)
	}

	if a.Runner.Limits.MaxToolCalls < 2 {
		out.Incomplete = true
		return out, errors.New("two graph tool operations must be permitted")
	}

	searchStarted := time.Now()
	var search GraphSearchResult
	var err error
	if fqdnInventory {
		search, err = searchFQDNInventory(ctx, a.Runner.Graph, a.Runner.Limits, root, opts)
	} else if typedRelation {
		search, err = searchTypedRelationIntent(ctx, a.Runner.Graph, a.Runner.Limits, root, typedIntent, opts)
	} else {
		search, err = a.guidedInvestigation(ctx, question, goal, root, opts, &out)
	}
	if err != nil {
		out.Incomplete = true
		out.recordTrace(searchStarted,
			InvestigationTraceEvent{Stage: "guided_search", Incomplete: true, Detail: err.Error()})
		return out, err
	}

	out.recordTrace(searchStarted,
		InvestigationTraceEvent{
			Stage:          "guided_search",
			OutputPaths:    len(search.Matches),
			GraphNodes:     search.VisitedNodes,
			GraphEdges:     search.VisitedEdges,
			PathExpansions: search.ExpandedPaths,
			Incomplete:     search.Truncated,
			Detail:         search.Reason,
		})
	out.ToolCalls++
	out.Search = &search
	obs, _ := json.Marshal(struct {
		Matches      int    `json:"matches"`
		VisitedNodes int    `json:"visited_nodes"`
		VisitedEdges int    `json:"visited_edges"`
		Truncated    bool   `json:"truncated"`
		Reason       string `json:"reason,omitempty"`
	}{len(search.Matches), search.VisitedNodes, search.VisitedEdges, search.Truncated, search.Reason})
	out.Observations = append(out.Observations,
		Observation{Tool: "search_graph", CallID: "adaptive-search", Result: string(obs)})
	attrCatalog, _ := a.Runner.Catalog.(graph.AttributionCatalog)
	candidates := eligibleAdaptivePathsWith(goal, search.Matches, attrCatalog)
	if goal.Purpose == "ultimate_parent" && attrCatalog != nil {
		out.ThirdParties = thirdPartyConnections(attrCatalog, search.Matches)
	}

	// An inventory can list more names than evidence inspection allows, so
	// provenance is sampled from the first paths; the rest are reported as
	// unassessed rather than dropped.
	inspect := candidates
	if fqdnInventory && len(inspect) > a.Runner.Limits.MaxFind {
		inspect = inspect[:a.Runner.Limits.MaxFind]
	}

	evidenceStarted := time.Now()
	dossier, err := EvaluatePathEvidence(ctx, a.Runner.Graph, a.Runner.Limits, inspect)
	if err != nil {
		out.Incomplete = true
		out.recordTrace(evidenceStarted,
			InvestigationTraceEvent{
				Stage:      "evidence_inspection",
				InputPaths: len(candidates),
				Incomplete: true,
				Detail:     err.Error(),
			})
		return out, fmt.Errorf("evaluate OAM source provenance: %w", err)
	}

	recordCount := 0
	seenEvidenceEdges := map[string]bool{}
	for _, p := range dossier.Paths {
		for _, edge := range p.Edges {
			if seenEvidenceEdges[edge.EdgeID] {
				continue
			}

			seenEvidenceEdges[edge.EdgeID] = true
			recordCount += len(edge.Records)
		}
	}

	out.recordTrace(evidenceStarted,
		InvestigationTraceEvent{
			Stage:               "evidence_inspection",
			InputPaths:          len(candidates),
			OutputPaths:         len(dossier.Paths),
			EdgeEvidenceLookups: dossier.InspectedEdges,
			EvidenceRecords:     recordCount,
			Incomplete:          dossier.Truncated,
			Detail:              dossier.Reason,
		})
	out.EvidenceDossier = &dossier
	selectionStarted := time.Now()
	var selected []graph.PlanMatch
	var groups []AnswerGroup
	var deterministic bool
	if fqdnInventory || typedRelation {
		// Every exactly witnessed typed inventory destination directly answers
		// the explicitly scoped question. Do not ask the LLM to discard results.
		deterministic = true
		selected = append([]graph.PlanMatch(nil), candidates...)
		groups = make([]AnswerGroup, 0, len(selected))
		for _, p := range selected {
			last := p.Nodes[len(p.Nodes)-1]
			groups = append(groups, AnswerGroup{AssetID: last.ID, AssetType: last.Type,
				Display: humanAsset(last), SemanticSignature: pathSemanticSignature(p),
				PreferredPathID: p.PathID, AlternativePathIDs: []string{}, DirectToGoal: true})
		}
	} else {
		selected, groups, deterministic, err = a.selectAnswerPaths(ctx, question, goal, candidates, &dossier)
	}

	out.AnswerGroups = groups
	if err != nil {
		out.Incomplete = true
		out.recordTrace(selectionStarted,
			InvestigationTraceEvent{
				Stage:      "path_selection",
				InputPaths: len(candidates),
				Incomplete: true,
				Detail:     err.Error(),
			})
		return out, err
	}

	selectionDetail := "model_evaluation"
	if deterministic {
		selectionDetail = "deterministic_destination_grouping"
	}

	selectionIncomplete := len(selected) == 0
	// No matches is a complete *typed inventory* result when all applicable
	// hops were evaluated within bounds. It is not a failed path selection.
	if fqdnInventory || typedRelation {
		selectionIncomplete = search.Truncated
	}

	out.recordTrace(selectionStarted,
		InvestigationTraceEvent{
			Stage:       "path_selection",
			InputPaths:  len(candidates),
			OutputPaths: len(selected),
			Incomplete:  selectionIncomplete,
			Detail:      selectionDetail,
		})
	out.Matches = selected
	out.EvidenceIncomplete = dossier.Truncated
	assessed := map[string]PathEvidence{}
	for _, p := range dossier.Paths {
		assessed[p.PathID] = p
	}
	for _, path := range selected {
		id := path.PathID
		if id == "" {
			id = graph.WitnessPathID(path)
		}

		ev, ok := assessed[id]
		if !ok || ev.Status != "multiple_source_tags_on_each_edge" {
			out.EvidenceIncomplete = true
		}
	}

	out.Incomplete = search.Truncated || (!fqdnInventory && !typedRelation && len(selected) == 0)
	if fqdnInventory || typedRelation {
		if fqdnInventory {
			out.Answer = fqdnInventoryAnswerScoped(root, selected, search.Truncated, search.Reason, q.ExcludeRoot)
			if len(selected) > maxInventoryDiagramPaths {
				return out, nil
			}
		} else {
			out.Answer = typedRelationAnswer(root, typedIntent, selected, search.Truncated, search.Reason)
			if len(selected) == 0 {
				out.Answer += typedRelationEmptyExplanation(search, typedIntent)
			}
		}

		out.Diagram = adaptiveDiagram(selected)
		return out, nil
	}
	if len(selected) == 0 {
		out.Answer = "No sufficiently supported answer was identified in the witnessed OAM paths. This does not prove that the requested relationship is absent."
		if goal.Purpose == "ultimate_parent" && attrCatalog != nil {
			out.Answer = "No organization is documented as the owner of " + humanAsset(root) +
				" in the stored OAM paths, so no parent organization can be named. This does not prove that none exists."
		}
		if !search.Truncated && !goal.Subject.UsesOrganizationResolution() {
			proposal := PlanCollection(goal.Subject.AssetSelector())
			if proposal.Status == "approval_required" {
				out.Collection = &proposal
			}
		}
	} else {
		paths := make([]string, 0, len(selected))
		for _, p := range selected {
			paths = append(paths, formatMatch(p))
		}
		if goal.Purpose == "ultimate_parent" {
			out.Answer = "Highest documented parent organization candidate(s) from stored OAM paths (not independently verified ultimate legal ownership): " + strings.Join(paths, "; ")
		} else {
			out.Answer = fmt.Sprintf("Found %d relevant stored OAM path(s): %s", len(selected),
				strings.Join(paths, "; "))
		}

		out.Diagram = adaptiveDiagram(selected)
		if out.EvidenceIncomplete {
			out.Answer += " Source-level support is incomplete or unattributed on one or more witnessed edges; their relationships are not independently verified."
		} else {
			out.Answer += " Multiple source tags were found on the selected graph evidence, but source independence and relationship truth are not verified."
		}
	}
	if goal.Purpose == "ultimate_parent" {
		out.Answer += thirdPartySummary(out.ThirdParties)
	}
	if search.Truncated {
		out.Answer += " Search truncated (" + search.Reason + "); additional relevant paths may exist."
	}

	return out, nil
}
