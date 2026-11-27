// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

type ToolSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

func ObjectSchema(required []string, properties map[string]any) map[string]any {
	return map[string]any{
		"type":                 "object",
		"properties":           properties,
		"required":             required,
		"additionalProperties": false,
	}
}

func StringProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func integerProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

func Specs() []ToolSpec {
	return []ToolSpec{
		{"get_asset", "Retrieve one asset by its database ID", ObjectSchema([]string{"id"},
			map[string]any{"id": StringProp("OAM database asset ID")})},
		{
			"describe_oam_schema",
			"List supported OAM relations, labels, relation types, and valid source/destination types. Use before choosing graph relationship labels.",
			ObjectSchema([]string{},
				map[string]any{"source_type": StringProp("Optional source asset type, e.g. Organization")}),
		},
		{
			"describe_asset_selectors",
			"List all OAM asset types and their supported indexed exact-match fields (entity_id works for every type).",
			ObjectSchema([]string{}, map[string]any{}),
		},
		{
			"resolve_asset",
			"Resolve any OAM asset type by field/value or explicit entity_id; returns candidates and ambiguity.",
			ObjectSchema([]string{"type"},
				map[string]any{
					"type":      StringProp("Exact OAM asset type"),
					"field":     StringProp("Indexed field for type"),
					"value":     StringProp("Exact field value"),
					"entity_id": StringProp("Exact database entity id"),
					"limit":     integerProp("Maximum candidates 1-10"),
				}),
		},
		{
			"resolve_organization",
			"Resolve a company by one asserted name, legal_name, unique_id, or jurisdiction-scoped registration_id. Returns match sources and ambiguity.",
			ObjectSchema([]string{},
				map[string]any{
					"name":            StringProp("Display or trade name"),
					"legal_name":      StringProp("Registered legal name"),
					"unique_id":       StringProp("OAM unique_id"),
					"registration_id": StringProp("Registration identifier"),
					"jurisdiction":    StringProp("Jurisdiction qualifier, required for registration_id"),
					"limit":           integerProp("Maximum candidates (1-10)"),
				}),
		},
		{
			"lookup_organization",
			"Look up an Organization asset by its exact display name (case handling depends on the repository); returns multiple matches for disambiguation",
			ObjectSchema([]string{"name"},
				map[string]any{
					"name":  StringProp("Exact organization name, e.g. Acme Holdings Inc."),
					"limit": integerProp("Maximum matches (1-10)"),
				}),
		},
		{
			"find_assets",
			"List assets by an exact OAM asset type and optional RFC3339 last-seen lower bound",
			ObjectSchema([]string{"type"},
				map[string]any{
					"type":  StringProp("e.g. Organization, FQDN, Service"),
					"since": StringProp("RFC3339 lower bound, not first-seen"),
					"limit": integerProp("Maximum results"),
				}),
		},
		{
			"walk_relations",
			"Bounded graph traversal from a known asset ID",
			ObjectSchema([]string{"start_id"},
				map[string]any{
					"start_id":  StringProp("Root asset ID"),
					"direction": StringProp("in, out, or both"),
					"label":     StringProp("Exact relation label, optional"),
					"depth":     integerProp("Graph hops"),
					"since":     StringProp("RFC3339 last-seen lower bound"),
				}),
		},
		{
			"get_evidence",
			"Retrieve tags/properties for an asset ID or relation ID",
			ObjectSchema([]string{"id"},
				map[string]any{"id": StringProp("Asset or edge ID"), "limit": integerProp("Maximum evidence records")}),
		},
		{
			"get_edge_evidence",
			"Retrieve source and property tags for an exact OAM relation ID; never confuses an edge ID with an asset ID",
			ObjectSchema([]string{"id"},
				map[string]any{
					"id":    StringProp("Exact OAM edge ID"),
					"limit": integerProp("Maximum provenance records"),
				}),
		},
		{
			"render_graph",
			"Generate a Mermaid diagram for a bounded OAM neighborhood",
			ObjectSchema([]string{"start_id"},
				map[string]any{
					"start_id":  StringProp("Root asset ID"),
					"direction": StringProp("in, out or both"),
					"label":     StringProp("Optional relation label"),
					"depth":     integerProp("Graph hops"),
					"since":     StringProp("RFC3339 lower bound"),
				}),
		},
	}
}
