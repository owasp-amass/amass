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

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

type ToolRunner struct {
	Graph   graph.Graph
	Limits  graph.Limits
	Catalog graph.SchemaCatalog
	// KnownVerification reports whether a TXT record is a verification token
	// the DNS-SD plugin recognizes, for the vendors lens (see VendorOptions).
	KnownVerification func(record string) bool
	// LensLimits bounds the lenses investigations run; zero keeps the
	// lenses' defaults.
	LensLimits lens.LensLimits
}

func (r ToolRunner) Run(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	if r.Graph == nil {
		return nil, errors.New("graph not configured")
	}
	if err := r.Limits.Validate(); err != nil {
		return nil, err
	}

	var result any
	switch name {
	case "get_asset":
		var a struct {
			ID string `json:"id"`
		}
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, err
		}
		if a.ID == "" {
			return nil, errors.New("id required")
		}

		v, err := r.Graph.GetAsset(ctx, a.ID)
		if err != nil {
			return nil, err
		}

		result = v

	case "describe_oam_schema":
		var a struct {
			SourceType string `json:"source_type"`
		}
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, err
		}
		if r.Catalog == nil {
			return nil, errors.New("OAM schema catalog not configured")
		}

		var relations []graph.RelationshipSchema
		for _, rel := range r.Catalog.Relations() {
			if a.SourceType == "" || rel.SourceType == a.SourceType {
				relations = append(relations, rel)
			}
		}

		result = relations

	case "describe_asset_selectors":
		var a struct{}
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, err
		}

		catalog, ok := r.Catalog.(graph.AssetSearchCatalog)
		if !ok {
			return nil, errors.New("asset selector catalog unavailable")
		}

		result = catalog.SearchFields()
	case "resolve_asset":
		var request struct {
			graph.AssetSelector
			Limit int `json:"limit"`
		}
		if err := graph.DecodeStrict(args, &request); err != nil {
			return nil, err
		}

		catalog, ok := r.Catalog.(graph.AssetSearchCatalog)
		if !ok {
			return nil, errors.New("asset selector catalog unavailable")
		}
		if err := request.Validate(catalog.SearchFields()); err != nil {
			return nil, err
		}
		if request.Limit == 0 {
			request.Limit = 10
		}
		if request.Limit < 1 || request.Limit > 10 || request.Limit > r.Limits.MaxFind {
			return nil, errors.New("asset lookup limit exceeds policy")
		}

		resolver, ok := r.Graph.(graph.AssetResolver)
		if !ok {
			return nil, errors.New("asset resolver unavailable")
		}

		v, err := resolver.ResolveAsset(ctx, request.AssetSelector, request.Limit)
		if err != nil {
			return nil, err
		}
		if len(v.Candidates) > request.Limit {
			return nil, errors.New("asset resolver exceeded candidate limit")
		}

		result = v
	case "resolve_organization":
		var a struct {
			graph.OrganizationQuery
			Limit int `json:"limit"`
		}
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, err
		}
		if err := a.Validate(); err != nil {
			return nil, err
		}
		if a.Limit == 0 {
			a.Limit = 10
		}
		if a.Limit < 1 || a.Limit > 10 || a.Limit > r.Limits.MaxFind {
			return nil, errors.New("resolution limit exceeds policy")
		}

		resolver, ok := r.Graph.(graph.OrganizationResolver)
		if !ok {
			return nil, errors.New("graph does not support organization resolution")
		}

		v, err := resolver.ResolveOrganizations(ctx, a.OrganizationQuery, a.Limit)
		if err != nil {
			return nil, err
		}
		if len(v.Candidates) > a.Limit {
			return nil, errors.New("organization resolver exceeded candidate limit")
		}

		result = v
	case "lookup_organization":
		var a struct {
			Name  string `json:"name"`
			Limit int    `json:"limit"`
		}
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, err
		}

		a.Name = strings.TrimSpace(a.Name)
		if a.Name == "" || len(a.Name) > 256 {
			return nil, errors.New("organization name must be 1..256 bytes")
		}
		if a.Limit == 0 {
			a.Limit = 10
		}
		if a.Limit < 1 || a.Limit > 10 || a.Limit > r.Limits.MaxFind {
			return nil, errors.New("organization lookup limit exceeds policy")
		}

		lookup, ok := r.Graph.(graph.OrganizationLookup)
		if !ok {
			return nil, errors.New("graph does not support exact organization lookup")
		}

		v, err := lookup.LookupOrganizations(ctx, a.Name, a.Limit)
		if err != nil {
			return nil, err
		}
		if len(v) > a.Limit {
			return nil, errors.New("organization lookup exceeded result limit")
		}

		result = v
	case "find_assets":
		var a struct {
			Type  string `json:"type"`
			Since string `json:"since"`
			Limit int    `json:"limit"`
		}
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, err
		}
		if a.Type == "" {
			return nil, errors.New("type required")
		}

		since, err := graph.DateSince(a.Since)
		if err != nil {
			return nil, err
		}
		if a.Limit == 0 {
			a.Limit = r.Limits.MaxFind
		}
		if a.Limit < 1 || a.Limit > r.Limits.MaxFind {
			return nil, fmt.Errorf("limit exceeds %d", r.Limits.MaxFind)
		}

		v, err := r.Graph.FindAssets(ctx, a.Type, since, a.Limit)
		if err != nil {
			return nil, err
		}

		result = v
	case "walk_relations":
		var a graph.WalkRequest
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, err
		}

		v, err := graph.Walk(ctx, r.Graph, r.Limits, a)
		if err != nil {
			return nil, err
		}

		result = v
	case "render_graph":
		var a graph.WalkRequest
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, err
		}

		v, err := graph.Walk(ctx, r.Graph, r.Limits, a)
		if err != nil {
			return nil, err
		}

		result = map[string]any{"mermaid": Mermaid(v), "truncated": v.Truncated, "reason": v.Reason}
	case "get_edge_evidence":
		var a struct {
			ID    string `json:"id"`
			Limit int    `json:"limit"`
		}
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, err
		}
		if a.ID == "" {
			return nil, errors.New("edge id required")
		}
		if a.Limit == 0 {
			a.Limit = r.Limits.MaxEvidence
		}
		if a.Limit < 1 || a.Limit > r.Limits.MaxEvidence {
			return nil, errors.New("evidence limit exceeds policy")
		}

		reader, ok := r.Graph.(graph.EdgeEvidenceReader)
		if !ok {
			return nil, errors.New("graph adapter lacks explicit edge-evidence support")
		}

		v, err := reader.EdgeEvidence(ctx, a.ID, a.Limit)
		if err != nil {
			return nil, err
		}

		result = v
	case "get_evidence":
		var a struct {
			ID    string `json:"id"`
			Limit int    `json:"limit"`
		}
		if err := graph.DecodeStrict(args, &a); err != nil {
			return nil, err
		}
		if a.ID == "" {
			return nil, errors.New("id required")
		}
		if a.Limit == 0 {
			a.Limit = r.Limits.MaxEvidence
		}
		if a.Limit < 1 || a.Limit > r.Limits.MaxEvidence {
			return nil, errors.New("evidence limit exceeds policy")
		}

		v, err := r.Graph.Evidence(ctx, a.ID, a.Limit)
		if err != nil {
			return nil, err
		}

		result = v
	default:
		return nil, fmt.Errorf("tool %q is not allowed", name)
	}

	b, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if len(b) > r.Limits.MaxToolBytes {
		return nil, errors.New("result exceeds tool byte budget; narrow the query")
	}

	return b, nil
}
