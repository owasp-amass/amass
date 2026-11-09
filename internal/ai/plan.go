// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
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
	return OrganizationQuery{Name: s.Name, LegalName: s.LegalName, UniqueID: s.UniqueID, RegistrationID: s.RegistrationID, Jurisdiction: s.Jurisdiction}
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
type partialPath struct {
	nodes []Asset
	edges []Relation
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
		if plan.Subject.Name != "" || plan.Subject.LegalName != "" || plan.Subject.UniqueID != "" || plan.Subject.RegistrationID != "" || plan.Subject.Jurisdiction != "" {
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

func parseTypedPlanWithSelectors(raw string, selectors []AssetSearchSchema) (TypedPlan, error) {
	var plan TypedPlan
	raw = strings.TrimSpace(raw)
	raw = ModelJSON(raw)
	data, err := canonicalizeSelectorFields([]byte(strings.TrimSpace(raw)), selectors)
	if err != nil {
		return plan, err
	}
	if err := decodeStrict(data, &plan); err != nil {
		return plan, fmt.Errorf("model did not return a valid typed JSON plan: %w", err)
	}
	return plan, nil
}

func parseTypedPlan(raw string) (TypedPlan, error) {
	var plan TypedPlan
	raw = strings.TrimSpace(raw)
	raw = ModelJSON(raw)
	if err := decodeStrict([]byte(strings.TrimSpace(raw)), &plan); err != nil {
		return plan, fmt.Errorf("model did not return a valid typed JSON plan: %w", err)
	}
	return plan, nil
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

func (a Agent) planQuestion(ctx context.Context, question string) (TypedPlan, error) {
	var zero TypedPlan
	if a.Runner.Catalog == nil {
		return zero, errors.New("OAM schema catalog is unavailable")
	}
	catalog := a.Runner.Catalog.Relations()
	var selectors []AssetSearchSchema
	if c, ok := a.Runner.Catalog.(AssetSearchCatalog); ok {
		selectors = c.SearchFields()
	}
	compactRelations := compactRelationshipCatalog(catalog)
	compactSelectors := compactSelectorCatalog(selectors)
	system := "You are an OWASP Open Asset Model query planner. Return ONLY one JSON object (no markdown). " +
		"Format: {\"subject\":{...},\"hops\":[{\"direction\":\"out or in\",\"label\":\"exact OAM label\",\"relation_type\":\"exact OAM relation type\",\"destination_type\":\"exact OAM asset type\"}]}. " +
		"Subject examples (use the type that the question starts with): " +
		"FQDN: {\"type\":\"FQDN\",\"field\":\"name\",\"value\":\"tech.acme.example\"}; " +
		"URL: {\"type\":\"URL\",\"field\":\"url\",\"value\":\"https://tech.acme.example/\"}; " +
		"IPAddress: {\"type\":\"IPAddress\",\"field\":\"address\",\"value\":\"192.0.2.1\"}; " +
		"Organization: {\"type\":\"Organization\",\"name\":\"Acme Holdings Inc.\"}. " +
		"Do NOT omit field or value for FQDN, URL, IPAddress or any other non-Organization type. " +
		"Choose exact indexed selector keys from the SELECTOR CATALOG, not guessed keys. " +
		"IMPORTANT: The selector catalog is input metadata only. NEVER echo fields arrays, a fields property, or catalog entries into your output. " +
		"Your subject may contain only type, field, value, entity_id, name, legal_name, unique_id, registration_id and jurisdiction. " +
		"Each hop may contain only direction, label, relation_type and destination_type. No other JSON keys are allowed. " +
		"Treat the request as an investigation over STORED graph relationships, not general knowledge. " +
		"Only choose transitions appearing in the catalog. Each hop begins at the previous hop's destination type. " +
		"For incoming hops reverse the permitted source/destination types. Prefer the shortest meaningful path (maximum 3 hops). " +
		"The subject may be ANY registered OAM asset type. For non-Organization subjects use type plus field/value from the SELECTOR CATALOG or type plus entity_id. " +
		"For Organization subjects either use the existing name/legal_name/unique_id/registration_id format, or type plus indexed field/value or entity_id. " +
		"Never invent an entity_id or a database identifier. The value must be quoted exactly from the user's question. " +
		"Use legal_name only for explicitly stated legal names, unique_id only for explicitly stated OAM IDs, and registration_id only when both registration number and jurisdiction are given. " +
		"Preserve the user-supplied organization string without inventing suffixes, aliases or jurisdictions. " +
		"Do not invent labels or add confidence claims. If you cannot construct a valid plan, return empty hops. " +
		"Map companies and businesses to Organization, hostnames and subdomains to FQDN, IP addresses to IPAddress, and physical addresses to Location. Bare addresses can mean IPAddress or Location; do not guess. Subdomains imply the FQDN node hierarchy, not arbitrary edges. " +
		"OAM ASSET LANGUAGE ALIASES (interpretation only):\n" + compactIntentVocabulary(selectors, catalog) +
		"\nUSER QUESTION OPERATION PARAPHRASES (do not invent OAM relations):\n" + compactOperationVocabulary() +
		"\nOAM RELATIONSHIP ALIASES (only registered labels are valid):\n" + compactRelationshipVocabulary(catalog) +
		"\nINDEXED FIELD ALIASES (only registered selectors are valid):\n" + compactSearchVocabulary(selectors) +
		"\nOAM RELATIONSHIP CATALOG (compact):\n" + compactRelations +
		" OAM SELECTOR CATALOG (compact):\n" + compactSelectors
	conversation := []Message{{Role: "system", Text: system}, {Role: "user", Text: question}}
	const maxPlanAttempts = 3
	for attempt := 0; attempt < maxPlanAttempts; attempt++ {
		response, err := a.Model.Generate(ctx, conversation, nil)
		if err != nil {
			return zero, err
		}
		if len(response.Calls) > 0 {
			return zero, errors.New("planner attempted a tool call instead of returning typed JSON")
		}
		plan, err := parseTypedPlanWithSelectors(response.Text, selectors)
		if err == nil {
			plan.Subject = normalizePlannedSubject(plan.Subject, selectors)
			err = validatePlanWithSelectors(plan, catalog, selectors, a.Runner.Limits)
		}
		if err == nil {
			return plan, nil
		}
		if attempt == maxPlanAttempts-1 {
			return zero, fmt.Errorf("unable to produce valid OAM query plan after %d attempts: %w", maxPlanAttempts, err)
		}
		hint := selectorCorrectionHint(plan.Subject, selectors)
		if strings.Contains(err.Error(), `json: unknown field "fields"`) {
			hint = "You returned an unsupported key named fields. The output subject MUST use singular field and value strings, " +
				"not a fields array or catalog object. " + hint
		}
		conversation = append(conversation, Message{Role: "assistant", Text: response.Text},
			Message{Role: "user", Text: "Your plan is invalid: " + err.Error() + ". " +
				"Correct the subject first. " + hint + " " +
				"Then validate each hop using the OAM RELATIONSHIP CATALOG, including direction and destination type. " +
				"Return the COMPLETE corrected JSON plan only."})
	}
	return zero, errors.New("query planner exhausted correction attempts")
}

// AskPlanned always validates a typed plan before touching the Asset Database.
// It does not use phrase matching or trust model-generated relationship claims.
func (a Agent) AskPlanned(ctx context.Context, question string) (Investigation, error) {
	var out Investigation
	if a.Model == nil || a.Runner.Graph == nil || a.Runner.Catalog == nil {
		return out, errors.New("model, graph, and schema catalog are required")
	}
	if err := a.Runner.Limits.Validate(); err != nil {
		return out, err
	}
	plan, err := a.planQuestion(ctx, question)
	if err != nil {
		out.Incomplete = true
		return out, err
	}
	out.Plan = &plan
	var root Asset
	if plan.Subject.UsesOrganizationResolution() {
		lookupJSON, _ := json.Marshal(struct {
			OrganizationQuery
			Limit int `json:"limit"`
		}{OrganizationQuery: plan.Subject.OrganizationQuery(), Limit: 10})
		raw, err := a.Runner.Run(ctx, "resolve_organization", lookupJSON)
		if err != nil {
			out.Incomplete = true
			return out, fmt.Errorf("organization lookup failed: %w", err)
		}
		out.ToolCalls++
		out.Observations = append(out.Observations, Observation{Tool: "resolve_organization", CallID: "planned-root", Result: string(raw)})
		var resolution OrganizationResolution
		if err := json.Unmarshal(raw, &resolution); err != nil {
			return out, fmt.Errorf("decode organization resolution: %w", err)
		}
		out.Resolution = &resolution
		if resolution.Status != "matched" || len(resolution.Candidates) != 1 {
			out.Incomplete = true
			out.Answer = resolutionAnswer(resolution.Status, resolution.Candidates)
			return out, nil
		}
		root = resolution.Candidates[0].Asset
	} else {
		lookupJSON, _ := json.Marshal(struct {
			AssetSelector
			Limit int `json:"limit"`
		}{AssetSelector: plan.Subject.AssetSelector(), Limit: 10})
		raw, err := a.Runner.Run(ctx, "resolve_asset", lookupJSON)
		if err != nil {
			out.Incomplete = true
			return out, fmt.Errorf("asset lookup failed: %w", err)
		}
		out.ToolCalls++
		out.Observations = append(out.Observations, Observation{Tool: "resolve_asset", CallID: "planned-root", Result: string(raw)})
		var resolution AssetResolution
		if err := json.Unmarshal(raw, &resolution); err != nil {
			return out, fmt.Errorf("decode asset resolution: %w", err)
		}
		out.AssetResolution = &resolution
		if resolution.Status != "matched" || len(resolution.Candidates) != 1 {
			out.Incomplete = true
			out.Answer = resolutionAnswer(resolution.Status, resolution.Candidates)
			return out, nil
		}
		root = resolution.Candidates[0].Asset
	}
	paths := []partialPath{{nodes: []Asset{root}}}
	edgesSeen := map[string]bool{}
	nodesSeen := map[string]bool{root.ID: true}
	stoppedAtHop := 0
	for hopIndex, step := range plan.Hops {
		next := make([]partialPath, 0)
		for _, path := range paths {
			if out.ToolCalls >= a.Runner.Limits.MaxToolCalls {
				out.Incomplete = true
				out.Answer = "Graph query stopped at its tool-call budget; no complete result can be asserted."
				return out, nil
			}
			startID := path.nodes[len(path.nodes)-1].ID
			req, _ := json.Marshal(WalkRequest{StartID: startID, Direction: step.Direction, Label: step.Label, Depth: 1})
			walkRaw, err := a.Runner.Run(ctx, "walk_relations", req)
			if err != nil {
				out.Incomplete = true
				return out, fmt.Errorf("hop %d traversal failed: %w", hopIndex+1, err)
			}
			out.ToolCalls++
			out.Observations = append(out.Observations, Observation{
				Tool: "walk_relations", CallID: fmt.Sprintf("planned-hop-%d-%d", hopIndex+1, out.ToolCalls), Result: string(walkRaw),
			})
			var walk WalkResult
			if err := json.Unmarshal(walkRaw, &walk); err != nil {
				return out, err
			}
			if walk.Truncated {
				out.Incomplete = true
			}
			byID := map[string]Asset{}
			for _, node := range walk.Nodes {
				byID[node.ID] = node
			}
			for _, edge := range walk.Edges {
				if edge.Label != step.Label || edge.Type != step.RelationType {
					continue
				}
				var destID string
				if step.Direction == "out" && edge.FromID == startID {
					destID = edge.ToID
				}
				if step.Direction == "in" && edge.ToID == startID {
					destID = edge.FromID
				}
				if destID == "" {
					continue
				}
				dest, ok := byID[destID]
				if !ok || dest.Type != step.DestinationType {
					out.Incomplete = true
					return out, fmt.Errorf("hop %d returned inconsistent OAM asset or relation type", hopIndex+1)
				}
				if !edgesSeen[edge.ID] && len(edgesSeen) >= a.Runner.Limits.MaxEdges ||
					!nodesSeen[dest.ID] && len(nodesSeen) >= a.Runner.Limits.MaxNodes ||
					len(next) >= a.Runner.Limits.MaxNodes {
					out.Incomplete = true
					break
				}
				edgesSeen[edge.ID] = true
				nodesSeen[dest.ID] = true
				np := partialPath{
					nodes: append(append([]Asset{}, path.nodes...), dest),
					edges: append(append([]Relation{}, path.edges...), edge),
				}
				next = append(next, np)
			}
		}
		paths = next
		if len(paths) == 0 {
			// A missing intermediate edge means subsequent planned hops were
			// never evaluated. This is not a completed investigation of the
			// requested target, even though the graph query itself succeeded.
			if hopIndex < len(plan.Hops)-1 {
				stoppedAtHop = hopIndex + 1
				out.PlanStoppedAtHop = stoppedAtHop
				out.Incomplete = true
			}
			break
		}
	}
	out.Matches = make([]PlanMatch, 0, len(paths))
	for _, path := range paths {
		out.Matches = append(out.Matches, PlanMatch{Nodes: path.nodes, Edges: path.edges})
	}
	sort.Slice(out.Matches, func(i, j int) bool { return formatMatch(out.Matches[i]) < formatMatch(out.Matches[j]) })
	if stoppedAtHop > 0 {
		hop := plan.Hops[stoppedAtHop-1]
		out.Answer = fmt.Sprintf("The proposed %d-hop OAM path stopped at hop %d (%s %s, relation type %s) because no matching edges were returned. "+
			"Later hops were not executed; the requested target remains unresolved. Other valid OAM paths may exist.",
			len(plan.Hops), stoppedAtHop, hop.Direction, hop.Label, hop.RelationType)
	} else if len(out.Matches) == 0 {
		out.Answer = fmt.Sprintf("No matching %d-hop OAM relationship paths were returned for %s by this database; this does not prove the relationships do not exist.", len(plan.Hops), formatPlanSubject(plan.Subject))
	} else {
		segments := make([]string, 0, len(out.Matches))
		for _, match := range out.Matches {
			segments = append(segments, formatMatch(match))
		}
		out.Answer = fmt.Sprintf("Found %d matching OAM path(s): %s. Results reflect stored graph relationships, not independent ownership verification.", len(segments), strings.Join(segments, "; "))
	}
	if out.Incomplete && stoppedAtHop == 0 {
		out.Answer += " The traversal was truncated or otherwise budget-limited; results may be incomplete."
	}
	return out, nil
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
			parts = append(parts, fmt.Sprintf("--%s [edge %s]-- %s (direction unknown)", e.Label, e.ID, humanAsset(next)))
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
