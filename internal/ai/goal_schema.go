// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import "sort"

// goalJSONSchema describes the planner's InvestigationGoal reply. Asset
// types and whole relationship transitions are enumerated from the OAM
// catalog, so a provider that enforces the schema cannot emit invented
// names or transitions. validateGoal still decides validity.
func goalJSONSchema(relations []RelationshipSchema, selectors []AssetSearchSchema) JSONSchema {
	return goalJSONSchemaFor(relations, selectors, relations)
}

// goalJSONSchemaFor enumerates every OAM asset type but only the transitions
// in promptRelations, the relationships the planner was shown. With none,
// the relationships list must be empty.
func goalJSONSchemaFor(relations []RelationshipSchema, selectors []AssetSearchSchema, promptRelations []RelationshipSchema) JSONSchema {
	types := map[string]bool{}
	for _, s := range selectors {
		types[s.Type] = true
	}
	for _, r := range relations {
		types[r.SourceType], types[r.DestinationType] = true, true
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
	// Each allowed relationship is one exact catalog transition. Listing
	// whole transitions (not independent enums per field) stops a
	// schema-enforcing provider from combining valid parts into a
	// transition OAM does not have, such as FQDN --website--> Organization.
	transitions := make([]any, 0, len(promptRelations))
	seen := map[string]bool{}
	for _, r := range promptRelations {
		key := relationKey(r.SourceType, r.Label, r.RelationType, r.DestinationType)
		if seen[key] {
			continue
		}

		seen[key] = true
		transitions = append(transitions, map[string]any{
			"source_type": r.SourceType, "label": r.Label,
			"relation_type": r.RelationType, "destination_type": r.DestinationType,
		})
	}

	relation := map[string]any{"enum": transitions}
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
				"relationships": relationshipsSchema(relation, len(transitions) > 0),
				"path_rule":     map[string]any{"type": "string", "enum": []string{"", "any", "all", "ordered"}},
				"answer":        map[string]any{"type": "string", "enum": answerKindNames()},
				"columns": map[string]any{
					"type":     "array",
					"maxItems": tableMaxColumns,
					// Exactly two column shapes: any asset type reached from the
					// previous cell, or the Organization that controls it.
					"items": map[string]any{"anyOf": []any{
						map[string]any{
							"type": "object",
							"properties": map[string]any{
								"type": assetType,
								"role": map[string]any{"type": "string", "enum": []string{ColumnReached}},
							},
							"required":             []string{"type", "role"},
							"additionalProperties": false,
						},
						map[string]any{
							"type": "object",
							"properties": map[string]any{
								"type": map[string]any{"type": "string", "enum": []string{"Organization"}},
								"role": map[string]any{"type": "string", "enum": []string{ColumnController}},
							},
							"required":             []string{"type", "role"},
							"additionalProperties": false,
						},
					}},
				},
			},
			"required": []string{
				"subject",
				"target_types",
				"direction",
				"purpose",
				"relationships",
				"path_rule",
				"answer",
				"columns",
			},
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
