// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import "sort"

// goalJSONSchema describes the planner's InvestigationGoal reply. Asset
// types, relation labels and relation types are enumerated from the OAM
// catalog, so a provider that enforces the schema cannot emit invented
// names. Pairings (which label joins which types) are still checked by
// validateGoal; the schema only narrows the vocabulary.
func goalJSONSchema(relations []RelationshipSchema, selectors []AssetSearchSchema) JSONSchema {
	return goalJSONSchemaFor(relations, selectors, relations)
}

// goalJSONSchemaFor enumerates every OAM asset type but only the labels and
// relation types of promptRelations, the relationships the planner was
// shown. With none, the relationships list must be empty.
func goalJSONSchemaFor(relations []RelationshipSchema, selectors []AssetSearchSchema, promptRelations []RelationshipSchema) JSONSchema {
	types, labels, relTypes := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range selectors {
		types[s.Type] = true
	}
	for _, r := range relations {
		types[r.SourceType], types[r.DestinationType] = true, true
	}
	for _, r := range promptRelations {
		labels[r.Label], relTypes[r.RelationType] = true, true
	}
	str := func() map[string]any { return map[string]any{"type": "string"} }
	enum := func(set map[string]bool) map[string]any {
		vals := make([]string, 0, len(set))
		for v := range set {
			vals = append(vals, v)
		}
		sort.Strings(vals)
		return map[string]any{"type": "string", "enum": vals}
	}
	assetType := enum(types)
	subject := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"type": assetType, "field": str(), "value": str(), "entity_id": str(),
			"name": str(), "legal_name": str(), "unique_id": str(),
			"registration_id": str(), "jurisdiction": str(),
		},
		"required":             []string{"type"},
		"additionalProperties": false,
	}
	relation := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"source_type": assetType, "label": enum(labels),
			"relation_type": enum(relTypes), "destination_type": assetType,
		},
		"required":             []string{"source_type", "label", "relation_type", "destination_type"},
		"additionalProperties": false,
	}
	return JSONSchema{
		Name:        "investigation_goal",
		Description: "The read-only OAM investigation goal for the user's question.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"subject":       subject,
				"target_types":  map[string]any{"type": "array", "items": assetType},
				"direction":     map[string]any{"type": "string", "enum": []string{"both", "in", "out"}},
				"purpose":       map[string]any{"type": "string", "enum": []string{"connected", "ultimate_parent"}},
				"relationships": relationshipsSchema(relation, len(labels) > 0),
				"path_rule":     map[string]any{"type": "string", "enum": []string{"", "any", "all", "ordered"}},
			},
			"required":             []string{"subject", "target_types", "direction", "purpose", "relationships", "path_rule"},
			"additionalProperties": false,
		},
	}
}

func relationshipsSchema(item map[string]any, allowed bool) map[string]any {
	if !allowed {
		return map[string]any{"type": "array", "maxItems": 0}
	}
	return map[string]any{"type": "array", "items": item}
}
