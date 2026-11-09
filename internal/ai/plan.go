// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const maxPlanHops = 3

// TypedPlan is the model-independent, read-only intermediate representation.
// The model selects among OAM transitions; Go validates the entire plan.
type TypedPlan struct {
	Subject PlanSubject `json:"subject"`
	Hops    []PlanHop   `json:"hops"`
}

type PlanSubject struct {
	Type           string `json:"type"`
	Name           string `json:"name,omitempty"`
	LegalName      string `json:"legal_name,omitempty"`
	UniqueID       string `json:"unique_id,omitempty"`
	RegistrationID string `json:"registration_id,omitempty"`
	Jurisdiction   string `json:"jurisdiction,omitempty"`
	Field          string `json:"field,omitempty"`
	Value          string `json:"value,omitempty"`
	EntityID       string `json:"entity_id,omitempty"`
}

func (s PlanSubject) AssetSelector() AssetSelector {
	return AssetSelector{Type: s.Type, Field: s.Field, Value: s.Value, EntityID: s.EntityID}
}

func (s PlanSubject) UsesOrganizationResolution() bool {
	return s.Type == "Organization" && s.Field == "" && s.Value == "" && s.EntityID == ""
}

func (s PlanSubject) OrganizationQuery() OrganizationQuery {
	return OrganizationQuery{
		Name:           s.Name,
		LegalName:      s.LegalName,
		UniqueID:       s.UniqueID,
		RegistrationID: s.RegistrationID,
		Jurisdiction:   s.Jurisdiction,
	}
}

type PlanHop struct {
	Direction       string `json:"direction"`
	Label           string `json:"label"`
	RelationType    string `json:"relation_type"`
	DestinationType string `json:"destination_type"`
}

type PlanMatch struct {
	Nodes  []Asset    `json:"nodes"`
	Edges  []Relation `json:"edges"`
	PathID string     `json:"path_id,omitempty"`
}

// validatePlan accepts only transitions explicitly present in the catalog.
// An unknown semantic label is never treated as a negative query result.
func validatePlan(plan TypedPlan, catalog []RelationshipSchema, limits Limits) error {
	return validatePlanWithSelectors(plan, catalog, nil, limits)
}

func validatePlanWithSelectors(plan TypedPlan, catalog []RelationshipSchema, selectors []AssetSearchSchema, limits Limits) error {
	if plan.Subject.UsesOrganizationResolution() {
		if err := plan.Subject.OrganizationQuery().Validate(); err != nil {
			return fmt.Errorf("invalid organization subject: %w", err)
		}
	} else {
		if err := plan.Subject.AssetSelector().Validate(selectors); err != nil {
			return fmt.Errorf("invalid asset subject: %w", err)
		}
		if plan.Subject.Name != "" || plan.Subject.LegalName != "" || plan.Subject.UniqueID != "" ||
			plan.Subject.RegistrationID != "" || plan.Subject.Jurisdiction != "" {
			return errors.New("typed asset selector cannot mix organization-specific fields")
		}
	}
	if len(plan.Hops) < 1 || len(plan.Hops) > maxPlanHops || len(plan.Hops) > limits.MaxDepth {
		return errors.New("plan must contain 1..3 bounded graph hops")
	}

	current := plan.Subject.Type
	for i, step := range plan.Hops {
		if step.Direction != "out" && step.Direction != "in" {
			return fmt.Errorf("hop %d direction must be out or in", i+1)
		}

		found := false
		for _, rel := range catalog {
			if step.Label != rel.Label || step.RelationType != rel.RelationType {
				continue
			}
			if step.Direction == "out" && current == rel.SourceType && step.DestinationType == rel.DestinationType ||
				step.Direction == "in" && current == rel.DestinationType && step.DestinationType == rel.SourceType {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("hop %d is not permitted by the OAM taxonomy: %s %s %s -> %s (%s)",
				i+1, current, step.Direction, step.Label, step.DestinationType, step.RelationType)
		}

		current = step.DestinationType
	}

	return nil
}

// normalizePlannedSubject repairs only an unambiguous *structural* omission:
// some models encode FQDN or other assets with an indexed "name" field as
// {"type":"FQDN","name":"host.example"}, reusing Organization syntax.
// If and only if the selected asset's schema has an indexed "name" field,
// move that name into the generic typed selector. This does not guess a
// missing value, choose an entity, or recognize natural-language phrases.
func normalizePlannedSubject(subject PlanSubject, selectors []AssetSearchSchema) PlanSubject {
	if subject.Type == "Organization" || subject.Name == "" ||
		subject.EntityID != "" || subject.Value != "" ||
		subject.LegalName != "" || subject.UniqueID != "" ||
		subject.RegistrationID != "" || subject.Jurisdiction != "" {
		return subject
	}
	for _, schema := range selectors {
		if schema.Type != subject.Type {
			continue
		}
		for _, field := range schema.Fields {
			if field == "name" && (subject.Field == "" || subject.Field == "name") {
				subject.Field = "name"
				subject.Value = subject.Name
				subject.Name = ""
				return subject
			}
		}
	}

	return subject
}

func selectorCorrectionHint(subject PlanSubject, selectors []AssetSearchSchema) string {
	for _, schema := range selectors {
		if schema.Type != subject.Type {
			continue
		}

		return fmt.Sprintf("For subject type %q, the valid indexed fields are %q. "+
			"Specify both subject.field and subject.value (copy the exact identifier "+
			"from the user question), or specify a user-provided subject.entity_id. "+
			"Do not use subject.name for a non-Organization type. "+
			"Example FQDN selector: {\"type\":\"FQDN\",\"field\":\"name\",\"value\":\"host.example\"}. "+
			"Do not invent an identifier.", subject.Type, schema.Fields)
	}

	return "The subject type must be registered in the OAM selector catalog."
}

// canonicalizeSelectorFields accepts one narrowly defined alternate JSON
// representation used by some local models: subject.fields={"name":"host.example"}.
// The single field must appear in the authoritative selector catalog. Any
// unsupported, ambiguous, or additional keys remain subject to strict JSON
// validation; this is not general-purpose schema coercion.
func canonicalizeSelectorFields(raw []byte, schemas []AssetSearchSchema) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return raw, nil
	}

	subjectRaw, ok := envelope["subject"]
	if !ok {
		return raw, nil
	}

	var subject map[string]json.RawMessage
	if err := json.Unmarshal(subjectRaw, &subject); err != nil {
		return raw, nil
	}

	fieldsRaw, ok := subject["fields"]
	if !ok {
		return raw, nil
	}

	var typ string
	if err := json.Unmarshal(subject["type"], &typ); err != nil {
		return raw, nil
	}
	if subject["field"] != nil || subject["value"] != nil ||
		subject["name"] != nil || subject["entity_id"] != nil ||
		subject["legal_name"] != nil || subject["unique_id"] != nil ||
		subject["registration_id"] != nil {
		return raw, nil
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(fieldsRaw, &fields); err != nil || len(fields) != 1 {
		return raw, nil
	}

	var field, value string
	for f, v := range fields {
		field = f
		if err := json.Unmarshal(v, &value); err != nil || value == "" {
			return raw, nil
		}
	}

	allowed := false
	for _, schema := range schemas {
		if schema.Type != typ {
			continue
		}
		for _, f := range schema.Fields {
			if f == field {
				allowed = true
				break
			}
		}
	}
	if !allowed {
		return raw, nil
	}

	subject["field"], _ = json.Marshal(field)
	subject["value"], _ = json.Marshal(value)
	delete(subject, "fields")
	envelope["subject"], _ = json.Marshal(subject)
	converted, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	return converted, nil
}

// compactRelationshipCatalog keeps the authoritative transition set intact
// but avoids repeating long JSON property names for every OAM relation.
// The model sees source|label|relation_type|destinations. All plan validation
// still uses the original unfiltered RelationshipSchema values.
func compactRelationshipCatalog(catalog []RelationshipSchema) string {
	groups := map[string]map[string]bool{}
	for _, rel := range catalog {
		key := rel.SourceType + "|" + rel.Label + "|" + rel.RelationType
		if groups[key] == nil {
			groups[key] = map[string]bool{}
		}

		groups[key][rel.DestinationType] = true
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("source|label|relation_type|destinations (comma-separated); incoming hops reverse source and destination:\n")
	for _, key := range keys {
		var dest []string
		for d := range groups[key] {
			dest = append(dest, d)
		}

		sort.Strings(dest)
		b.WriteString(key)
		b.WriteString("|")
		b.WriteString(strings.Join(dest, ","))
		b.WriteByte('\n')
	}

	return b.String()
}

// compactSelectorCatalog describes the indexed selector fields without
// encouraging models to copy a JSON "fields" property into the plan.
func compactSelectorCatalog(catalog []AssetSearchSchema) string {
	rows := make([]AssetSearchSchema, len(catalog))
	copy(rows, catalog)
	sort.Slice(rows, func(i, j int) bool { return rows[i].Type < rows[j].Type })
	var b strings.Builder
	b.WriteString("asset_type: valid selector field names; entity_id works for every type:\n")
	for _, entry := range rows {
		fields := append([]string(nil), entry.Fields...)
		sort.Strings(fields)
		if len(fields) == 0 {
			fields = []string{"(entity_id only)"}
		}

		b.WriteString(entry.Type)
		b.WriteString(": ")
		b.WriteString(strings.Join(fields, ","))
		b.WriteByte('\n')
	}

	return b.String()
}

func formatMatch(p PlanMatch) string {
	if len(p.Nodes) == 0 {
		return ""
	}

	parts := []string{humanAsset(p.Nodes[0])}
	for i, e := range p.Edges {
		if i+1 >= len(p.Nodes) {
			break
		}

		current, next := p.Nodes[i], p.Nodes[i+1]
		switch {
		case e.FromID == current.ID && e.ToID == next.ID:
			parts = append(parts, fmt.Sprintf("--%s [edge %s]--> %s", e.Label, e.ID, humanAsset(next)))
		case e.ToID == current.ID && e.FromID == next.ID:
			parts = append(parts, fmt.Sprintf("<--%s [edge %s]-- %s", e.Label, e.ID, humanAsset(next)))
		default:
			// Malformed edge endpoints must not be presented as a directed claim.
			parts = append(parts, fmt.Sprintf("--%s [edge %s]-- %s (direction unknown)", e.Label, e.ID,
				humanAsset(next)))
		}
	}

	return strings.Join(parts, " ")
}

func humanAsset(a Asset) string {
	display := a.Key
	// Content is an OAM struct in database adapters and a map after JSON
	// decoding. Pull display fields only from JSON to avoid model speculation.
	data, err := json.Marshal(a.Content)
	if err == nil {
		var fields map[string]json.RawMessage
		if json.Unmarshal(data, &fields) == nil {
			for _, key := range []string{"name", "url"} {
				var value string
				if json.Unmarshal(fields[key], &value) == nil && value != "" {
					display = value
					break
				}
			}
		}
	}

	return fmt.Sprintf("%s (asset %s)", display, a.ID)
}

func resolutionAnswer(status string, candidates []OrganizationCandidate) string {
	switch status {
	case "not_found":
		return "No asset matched the asserted typed identifier in the current Asset Database; no relationship conclusion can be drawn."
	case "truncated":
		return "The bounded asset lookup was truncated; identity cannot be selected safely."
	case "ambiguous":
		var choices []string
		for _, c := range candidates {
			var src []string
			for _, m := range c.Matches {
				if m.Source != "" {
					src = append(src, m.Field+"="+m.Value+" [source: "+m.Source+"]")
				} else {
					src = append(src, m.Field+"="+m.Value)
				}
			}

			choices = append(choices, humanAsset(c.Asset)+" ["+strings.Join(src, ", ")+"]")
		}

		return "Ambiguous asset identity; specify an explicit entity_id or a more selective typed field. Candidates: " + strings.Join(choices, "; ")
	default:
		return "Unable to resolve the starting asset safely."
	}
}

func formatPlanSubject(subject PlanSubject) string {
	if subject.EntityID != "" {
		return fmt.Sprintf("%s entity_id %q", subject.Type, subject.EntityID)
	}
	if subject.Value != "" {
		return fmt.Sprintf("%s %s=%q", subject.Type, subject.Field, subject.Value)
	}
	if subject.Name != "" {
		return fmt.Sprintf("%s %q", subject.Type, subject.Name)
	}
	if subject.LegalName != "" {
		return fmt.Sprintf("%s legal_name=%q", subject.Type, subject.LegalName)
	}
	if subject.UniqueID != "" {
		return fmt.Sprintf("%s unique_id=%q", subject.Type, subject.UniqueID)
	}
	if subject.RegistrationID != "" {
		return fmt.Sprintf("%s registration_id=%q in %q", subject.Type, subject.RegistrationID, subject.Jurisdiction)
	}

	return subject.Type
}
