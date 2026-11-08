// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type ToolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}
// RelationshipSchema represents one permitted directed OAM relationship.
type RelationshipSchema struct {
	SourceType string `json:"source_type"`
	Label string `json:"label"`
	RelationType string `json:"relation_type"`
	DestinationType string `json:"destination_type"`
}

// SchemaCatalog exposes authoritative OAM relationship metadata.
type SchemaCatalog interface {
	Relations() []RelationshipSchema
}

type ToolRunner struct {
	Graph   Graph
	Limits  Limits
	Catalog SchemaCatalog
}

func objectSchema(required []string, properties map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}
func stringProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func integerProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}
func Specs() []ToolSpec {
	return []ToolSpec{
		{"get_asset", "Retrieve one asset by its database ID", objectSchema([]string{"id"}, map[string]any{"id": stringProp("OAM database asset ID")})},
		{"describe_oam_schema", "List supported OAM relations, labels, relation types, and valid source/destination types. Use before choosing graph relationship labels.", objectSchema([]string{}, map[string]any{"source_type": stringProp("Optional source asset type, e.g. Organization")})},
		{"describe_asset_selectors", "List all OAM asset types and their supported indexed exact-match fields (entity_id works for every type).", objectSchema([]string{}, map[string]any{})},
		{"resolve_asset", "Resolve any OAM asset type by field/value or explicit entity_id; returns candidates and ambiguity.", objectSchema([]string{"type"},map[string]any{"type":stringProp("Exact OAM asset type"),"field":stringProp("Indexed field for type"),"value":stringProp("Exact field value"),"entity_id":stringProp("Exact database entity id"),"limit":integerProp("Maximum candidates 1-10")})},
		{"resolve_organization", "Resolve a company by one asserted name, legal_name, unique_id, or jurisdiction-scoped registration_id. Returns match sources and ambiguity.", objectSchema([]string{}, map[string]any{"name": stringProp("Display or trade name"), "legal_name": stringProp("Registered legal name"), "unique_id": stringProp("OAM unique_id"), "registration_id": stringProp("Registration identifier"), "jurisdiction": stringProp("Jurisdiction qualifier, required for registration_id"), "limit": integerProp("Maximum candidates (1-10)")})},
		{"lookup_organization", "Look up an Organization asset by its exact display name (case handling depends on the repository); returns multiple matches for disambiguation", objectSchema([]string{"name"}, map[string]any{"name": stringProp("Exact organization name, e.g. Acme Holdings Inc."), "limit": integerProp("Maximum matches (1-10)")})},
		{"find_assets", "List assets by an exact OAM asset type and optional RFC3339 last-seen lower bound", objectSchema([]string{"type"}, map[string]any{"type": stringProp("e.g. Organization, FQDN, Service"), "since": stringProp("RFC3339 lower bound, not first-seen"), "limit": integerProp("Maximum results")})},
		{"walk_relations", "Bounded graph traversal from a known asset ID", objectSchema([]string{"start_id"}, map[string]any{"start_id": stringProp("Root asset ID"), "direction": stringProp("in, out, or both"), "label": stringProp("Exact relation label, optional"), "depth": integerProp("Graph hops"), "since": stringProp("RFC3339 last-seen lower bound")})},
		{"get_evidence", "Retrieve tags/properties for an asset ID or relation ID", objectSchema([]string{"id"}, map[string]any{"id": stringProp("Asset or edge ID"), "limit": integerProp("Maximum evidence records")})},
		{"render_graph", "Generate a Mermaid diagram for a bounded OAM neighborhood", objectSchema([]string{"start_id"}, map[string]any{"start_id": stringProp("Root asset ID"), "direction": stringProp("in, out or both"), "label": stringProp("Optional relation label"), "depth": integerProp("Graph hops"), "since": stringProp("RFC3339 lower bound")})},
	}
}
func decodeStrict(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
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
		if err := decodeStrict(args, &a); err != nil {
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
		var a struct { SourceType string `json:"source_type"` }
		if err := decodeStrict(args, &a); err != nil {
			return nil, err
		}
		if r.Catalog == nil {
			return nil, errors.New("OAM schema catalog not configured")
		}
		var relations []RelationshipSchema
		for _, rel := range r.Catalog.Relations() {
			if a.SourceType == "" || rel.SourceType == a.SourceType {
				relations = append(relations, rel)
			}
		}
		result = relations


	case "describe_asset_selectors":
		var a struct{}
		if err:=decodeStrict(args,&a);err!=nil{return nil,err}
		catalog,ok:=r.Catalog.(AssetSearchCatalog)
		if !ok{return nil,errors.New("asset selector catalog unavailable")}
		result=catalog.SearchFields()
	case "resolve_asset":
		var request struct {
			AssetSelector
			Limit int `json:"limit"`
		}
		if err:=decodeStrict(args,&request);err!=nil{return nil,err}
		catalog,ok:=r.Catalog.(AssetSearchCatalog)
		if !ok{return nil,errors.New("asset selector catalog unavailable")}
		if err:=request.AssetSelector.Validate(catalog.SearchFields());err!=nil{return nil,err}
		if request.Limit==0{request.Limit=10}
		if request.Limit<1||request.Limit>10||request.Limit>r.Limits.MaxFind{return nil,errors.New("asset lookup limit exceeds policy")}
		resolver,ok:=r.Graph.(AssetResolver)
		if !ok{return nil,errors.New("asset resolver unavailable")}
		v,err:=resolver.ResolveAsset(ctx,request.AssetSelector,request.Limit)
		if err!=nil{return nil,err}
		if len(v.Candidates)>request.Limit{return nil,errors.New("asset resolver exceeded candidate limit")}
		result=v
	case "resolve_organization":
		var a struct {
			OrganizationQuery
			Limit int `json:"limit"`
		}
		if err := decodeStrict(args, &a); err != nil { return nil, err }
		if err := a.OrganizationQuery.Validate(); err != nil { return nil, err }
		if a.Limit==0 {a.Limit=10}
		if a.Limit<1 || a.Limit>10 || a.Limit>r.Limits.MaxFind {return nil,errors.New("resolution limit exceeds policy")}
		resolver,ok:=r.Graph.(OrganizationResolver)
		if !ok {return nil,errors.New("graph does not support organization resolution")}
		v,err:=resolver.ResolveOrganizations(ctx,a.OrganizationQuery,a.Limit)
		if err != nil {return nil,err}
		if len(v.Candidates)>a.Limit {return nil,errors.New("organization resolver exceeded candidate limit")}
		result=v
	case "lookup_organization":
		var a struct {
			Name string `json:"name"`
			Limit int `json:"limit"`
		}
		if err := decodeStrict(args, &a); err != nil {
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
		lookup, ok := r.Graph.(OrganizationLookup)
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
		if err := decodeStrict(args, &a); err != nil {
			return nil, err
		}
		if a.Type == "" {
			return nil, errors.New("type required")
		}
		since, err := DateSince(a.Since)
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
		var a WalkRequest
		if err := decodeStrict(args, &a); err != nil {
			return nil, err
		}
		v, err := Walk(ctx, r.Graph, r.Limits, a)
		if err != nil {
			return nil, err
		}
		result = v
	case "render_graph":
		var a WalkRequest
		if err := decodeStrict(args, &a); err != nil {
			return nil, err
		}
		v, err := Walk(ctx, r.Graph, r.Limits, a)
		if err != nil {
			return nil, err
		}
		result = map[string]any{"mermaid": Mermaid(v), "truncated": v.Truncated, "reason": v.Reason}
	case "get_evidence":
		var a struct {
			ID    string `json:"id"`
			Limit int    `json:"limit"`
		}
		if err := decodeStrict(args, &a); err != nil {
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
