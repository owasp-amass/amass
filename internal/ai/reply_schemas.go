// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import "sort"

// enumArray is a schema for an array of at most max distinct strings drawn
// from values. With no values the array must be empty.
func enumArray(values []string, max int) map[string]any {
	seen := map[string]bool{}
	unique := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			unique = append(unique, v)
		}
	}
	if len(unique) == 0 {
		return map[string]any{"type": "array", "maxItems": 0}
	}

	sort.Strings(unique)
	return map[string]any{
		"type":        "array",
		"items":       map[string]any{"type": "string", "enum": unique},
		"maxItems":    max,
		"uniqueItems": true,
	}
}

func objectOf(properties map[string]any) map[string]any {
	required := make([]string, 0, len(properties))
	for name := range properties {
		required = append(required, name)
	}

	sort.Strings(required)
	return map[string]any{
		"type":                 "object",
		"properties":           properties,
		"required":             required,
		"additionalProperties": false,
	}
}

// pathSelectionSchema limits a path selection to the candidate path IDs.
func pathSelectionSchema(candidates []adaptiveCandidate) JSONSchema {
	ids := make([]string, 0, len(candidates))
	for _, c := range candidates {
		ids = append(ids, c.PathID)
	}

	return JSONSchema{
		Name:        "path_selection",
		Description: "Witnessed path IDs that answer the question.",
		Schema:      objectOf(map[string]any{"selected_path_ids": enumArray(ids, 5)}),
	}
}

// guidanceSchema limits navigation advice to the allowed labels and the
// pending frontier's asset and path IDs.
func guidanceSchema(state guidedSummary) JSONSchema {
	assets := make([]string, 0, len(state.Pending))
	paths := make([]string, 0, len(state.Pending))
	for _, f := range state.Pending {
		assets = append(assets, f.AssetID)
		paths = append(paths, f.PathID)
	}

	return JSONSchema{
		Name:        "navigation_priorities",
		Description: "Relationship labels and frontier assets or paths to explore first.",
		Schema: objectOf(map[string]any{
			"preferred_labels":   enumArray(state.AllowedLabels, 5),
			"priority_asset_ids": enumArray(assets, 5),
			"priority_path_ids":  enumArray(paths, 5),
		}),
	}
}

// proposalSchema limits an inference proposal to the candidate's endpoints,
// allowed labels (or "none") and evidence IDs.
func proposalSchema(c Candidate) JSONSchema {
	evidence := make([]string, 0, len(c.Evidence))
	for _, e := range c.Evidence {
		evidence = append(evidence, e.ID)
	}

	predicates := append([]string{"none"}, c.AllowedLabels...)
	return JSONSchema{
		Name:        "relation_proposal",
		Description: "A proposed OAM relationship between the two candidate assets, or none.",
		Schema: objectOf(map[string]any{
			"subject_id":     map[string]any{"type": "string", "enum": []string{c.SubjectID}},
			"object_id":      map[string]any{"type": "string", "enum": []string{c.ObjectID}},
			"predicate":      map[string]any{"type": "string", "enum": predicates},
			"confidence":     map[string]any{"type": "number", "minimum": 0, "maximum": 1},
			"reason":         map[string]any{"type": "string"},
			"evidence_ids":   enumArray(evidence, len(evidence)),
			"contradictions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}),
	}
}
