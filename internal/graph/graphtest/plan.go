// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"context"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

type PlanCatalog []graph.RelationshipSchema

func (c PlanCatalog) Relations() []graph.RelationshipSchema { return c }

func (c PlanCatalog) SearchFields() []graph.AssetSearchSchema {
	return []graph.AssetSearchSchema{
		{Type: "Organization", Fields: []string{"name", "legal_name", "unique_id"}},
		{Type: "URL", Fields: []string{"url"}},
		{Type: "FQDN", Fields: []string{"name"}},
	}
}

var TestOAMCatalog = PlanCatalog{
	{SourceType: "Organization", Label: "subsidiary", RelationType: "SimpleRelation", DestinationType: "Organization"},
	{SourceType: "Organization", Label: "website", RelationType: "SimpleRelation", DestinationType: "URL"},
	{SourceType: "URL", Label: "domain", RelationType: "SimpleRelation", DestinationType: "FQDN"},
}

type PlannedGraph struct{ FakeGraph }

func (g PlannedGraph) LookupOrganizations(_ context.Context, name string, _ int) ([]graph.Asset, error) {
	if name != "Acme Holdings Inc." {
		return []graph.Asset{}, nil
	}

	return []graph.Asset{g.Assets["parent"]}, nil
}

func (g PlannedGraph) ResolveAsset(_ context.Context, selector graph.AssetSelector, _ int) (graph.AssetResolution, error) {
	result := graph.AssetResolution{Query: selector, Status: "not_found", Candidates: []graph.OrganizationCandidate{}}
	for _, asset := range g.Assets {
		if asset.Type != selector.Type {
			continue
		}
		if selector.EntityID == asset.ID ||
			selector.Type == "URL" && selector.Field == "url" && selector.Value == asset.Key ||
			selector.Type == "FQDN" && selector.Field == "name" && selector.Value == asset.Key {
			result.Candidates = append(result.Candidates,
				graph.OrganizationCandidate{
					Asset:   asset,
					Matches: []graph.ResolutionMatch{{Field: selector.Field, Value: selector.Value}},
				})
		}
	}
	if len(result.Candidates) == 1 {
		result.Status = "matched"
	} else if len(result.Candidates) > 1 {
		result.Status = "ambiguous"
	}

	return result, nil
}

func (g PlannedGraph) ResolveOrganizations(_ context.Context, q graph.OrganizationQuery, _ int) (graph.OrganizationResolution, error) {
	result := graph.OrganizationResolution{Query: q, Status: "not_found", Candidates: []graph.OrganizationCandidate{}}
	if q.Name == "Acme Holdings Inc." || q.LegalName == "Acme Holdings Inc." ||
		q.UniqueID == "synthetic-acme-holdings" {
		result.Status = "matched"
		result.Candidates = []graph.OrganizationCandidate{
			{Asset: g.Assets["parent"], Matches: []graph.ResolutionMatch{{Field: "name", Value: "Acme Holdings Inc."}}},
		}
	}

	return result, nil
}
