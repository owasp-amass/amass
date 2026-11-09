// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"regexp"
	"sort"
	"strings"
)

// planningFocus is the part of the OAM catalog a question mentions: asset
// types named by an alias or implied by an identifier in the question, and
// relation labels named by an alias. It only decides what the planner
// prompt shows; validation always uses the full catalog.
type planningFocus struct {
	Types  map[string]bool
	Labels map[string]bool
}

var (
	urlInQuestion  = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://\S+`)
	ipv4InQuestion = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	cidrInQuestion = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b`)
	asnInQuestion  = regexp.MustCompile(`(?i)\bAS\s?\d{1,10}\b`)
	ipv6InQuestion = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b`)
)

// questionFocus finds the types and labels a question mentions. Aliases
// must match whole words; identifiers imply their asset type.
func questionFocus(question string, relations []RelationshipSchema, selectors []AssetSearchSchema) planningFocus {
	f := planningFocus{Types: map[string]bool{}, Labels: map[string]bool{}}
	text := " " + normalizeSchemaAlias(question) + " "
	mentions := func(alias string) bool {
		a := normalizeSchemaAlias(alias)
		return a != "" && strings.Contains(text, " "+a+" ")
	}
	registered := map[string]bool{}
	for _, s := range selectors {
		registered[s.Type] = true
	}
	labels := map[string]bool{}
	for _, r := range relations {
		registered[r.SourceType], registered[r.DestinationType] = true, true
		labels[r.Label] = true
	}
	typeAliases := map[string]bool{}
	for typ := range registered {
		for _, alias := range intentAssetAliases(typ) {
			typeAliases[normalizeSchemaAlias(alias)] = true
			if mentions(alias) {
				f.Types[typ] = true
			}
		}
	}
	// A word that names an asset type ("organization", "location") is not a
	// request for the relationship of the same name.
	for label := range labels {
		for _, alias := range relationLabelAliases(label) {
			if typeAliases[normalizeSchemaAlias(alias)] {
				continue
			}
			if mentions(alias) {
				f.Labels[label] = true
				break
			}
		}
	}
	implied := func(typ string) {
		if registered[typ] {
			f.Types[typ] = true
		}
	}
	rest := question
	if urlInQuestion.MatchString(rest) {
		implied("URL")
		rest = urlInQuestion.ReplaceAllString(rest, " ")
	}
	if cidrInQuestion.MatchString(rest) {
		implied("Netblock")
		rest = cidrInQuestion.ReplaceAllString(rest, " ")
	}
	if ipv4InQuestion.MatchString(rest) || ipv6InQuestion.MatchString(rest) {
		implied("IPAddress")
		rest = ipv6InQuestion.ReplaceAllString(ipv4InQuestion.ReplaceAllString(rest, " "), " ")
	}
	if asnInQuestion.MatchString(rest) {
		implied("AutonomousSystem")
	}
	if hostnameInQuestion.MatchString(rest) && !strings.Contains(rest, "@") {
		implied("FQDN")
	}
	return f
}

// plannerPrompt is the system prompt and reply schema for one planning attempt.
type plannerPrompt struct {
	Text     string
	Schema   JSONSchema
	Explicit bool
	Hint     explicitRelationHint
	// Sliced reports that the prompt shows only the question's focus.
	Sliced bool
	// NamesRelationship reports that the question asks for particular
	// relationships, explicitly or by a relationship alias.
	NamesRelationship bool
}

// goalPlannerPrompt builds the goal planner prompt. With sliced set, only
// the relationships, type aliases and selectors the question mentions are
// shown, which cuts the prompt from about 3,500 tokens to well under half
// for most questions; CPU-only local models spend most of their time
// reading the prompt. Without slicing, the whole catalog is shown.
func goalPlannerPrompt(question string, relations []RelationshipSchema, selectors []AssetSearchSchema, sliced bool) plannerPrompt {
	out := plannerPrompt{}
	types := map[string]bool{}
	for _, s := range selectors {
		types[s.Type] = true
	}
	for _, r := range relations {
		types[r.SourceType], types[r.DestinationType] = true, true
	}
	allTypes := make([]string, 0, len(types))
	for typ := range types {
		allTypes = append(allTypes, typ)
	}
	sort.Strings(allTypes)

	out.Hint, out.Explicit = explicitRelationLabels(question, relations)
	focus := questionFocus(question, relations, selectors)
	out.NamesRelationship = out.Explicit || len(focus.Labels) > 0
	promptRelations := relations
	promptSelectors := selectors
	typeAliasTypes := types
	switch {
	case out.Explicit:
		// When the user explicitly names relationship types, only those
		// transitions need to be presented to the model.
		promptRelations = relationsWithLabels(relations, out.Hint.Labels)
	case sliced:
		labels := make([]string, 0, len(focus.Labels))
		for l := range focus.Labels {
			labels = append(labels, l)
		}
		promptRelations = relationsWithLabels(relations, labels)
	}
	if sliced && len(focus.Types) > 0 {
		out.Sliced = true
		typeAliasTypes = focus.Types
		promptSelectors = make([]AssetSearchSchema, 0, len(focus.Types))
		for _, s := range selectors {
			if focus.Types[s.Type] || s.Type == "Organization" {
				promptSelectors = append(promptSelectors, s)
			}
		}
	}
	if sliced && len(promptRelations) < len(relations) {
		out.Sliced = true
	}
	relationCatalog := compactRelationshipCatalog(promptRelations)
	if len(promptRelations) == 0 {
		relationCatalog = "(The question names no OAM relationship: use relationships [] and path_rule \"\".)\n"
	}
	selectorNote := ""
	if len(promptSelectors) < len(selectors) {
		selectorNote = " (types mentioned in the question; any OAM type below is valid)"
	}
	out.Text = `You are a read-only OAM investigation goal planner. Return ONLY one JSON object, without prose.
Exact shape: {"subject":{...},"target_types":["OAMType"],"direction":"both","purpose":"connected","relationships":[],"path_rule":""}.
The OPTIONAL relationships list contains exact stored OAM transitions as {"source_type":"...","label":"...","relation_type":"...","destination_type":"..."}. Never fabricate labels, direction, relation types, or source/destination types. Use the OAM RELATIONSHIP CATALOG below.
When the user requests particular relationship semantics, select the actual relevant relationship types, including all intermediate asset types. "path_rule" may be "" (no constraints), "any" (at least one listed relationship in the witnessed path), "all" (every listed relationship appears in the path), or "ordered" (listed relationships in traversal order starting at the user's subject; intermediate hops allowed, including when traversing stored edges backwards).
Use relationships:[] and path_rule:"" for broad exploration. Do not require specific labels for queries that only request connectivity.
Example: for a parent organization question, choose purpose "ultimate_parent", targets ["Organization"], and relationships:[] unless the question explicitly specifies additional relationship conditions.
Use purpose "ultimate_parent" ONLY when the question asks for the highest or ultimate parent organization. For this purpose, target_types MUST be ["Organization"] and direction MUST be "both".
Otherwise use purpose "connected". The user's starting asset may have ANY registered OAM type. Use type/field/value from the SELECTOR CATALOG, or type/entity_id if that identifier was supplied by the user. Organization can use its own name, legal_name, unique_id or jurisdiction-qualified registration_id fields. Copy identifiers exactly from the user, do NOT fabricate names, corporate suffixes, identifiers or jurisdictions.
For a non-Organization, use {"type":"FQDN","field":"name","value":"example.org"} (with the actual indexed type/field), NEVER subject.name. Do not output a "fields" array or echo the selector catalog.
Choose target_types from the catalog based on the answer requested. Map ordinary language to registered OAM types: companies/businesses/legal entities to Organization; hostnames/subdomains to FQDN; IP addresses to IPAddress; physical/postal addresses to Location. Bare "addresses" is ambiguous between IPAddress and Location: resolve only when the question provides enough context, not by guessing. "Subdomains" additionally requests the FQDN node hierarchy rather than arbitrary FQDN associations. Do not invent types. Set [] if the question is broad and exploratory.
All intermediate asset types may be visited regardless of target_types. No fixed hop list, no relation label prediction, and no "hops" field. Prefer direction "both" unless the user explicitly requests a traversal direction.
SELECTOR CATALOG` + selectorNote + `:
` + compactSelectorCatalog(promptSelectors) +
		"\nUSER LANGUAGE ALIASES FOR OAM TYPES (not new OAM types):\n" + compactIntentVocabularyFor(typeAliasTypes) +
		"\nALL AVAILABLE OAM TARGET TYPES: " + strings.Join(allTypes, ",") +
		"\nUSER QUESTION OPERATION PARAPHRASES (do not invent OAM edge labels):\n" + compactOperationVocabulary() +
		"\nOAM RELATIONSHIP LABEL LANGUAGE ALIASES (labels must exist in catalog):\n" + compactRelationshipVocabulary(promptRelations) +
		"\nOAM INDEXED SEARCH FIELD LANGUAGE ALIASES (selectors must exist in catalog):\n" + compactSearchVocabulary(promptSelectors) +
		"\nOAM RELATIONSHIP CATALOG:\n" + relationCatalog
	if out.Explicit {
		// Promote user-named OAM labels above model-assumed WHOIS/DNS hops.
		// Exact transition types are still grounded only after a typed root and
		// target have been provided and independently validated.
		out.Text += "\nExplicit relationship labels in the user question: " + strings.Join(out.Hint.Labels, ", ") +
			". Avoid unrelated registration and WHOIS hops. If multiple relations are requested, " +
			"retain each named label. The application will verify and resolve any ambiguity against OAM schema.\n"
	}
	out.Schema = goalJSONSchemaFor(relations, selectors, promptRelations)
	return out
}

func relationsWithLabels(relations []RelationshipSchema, labels []string) []RelationshipSchema {
	selected := map[string]bool{}
	for _, l := range labels {
		selected[strings.ToLower(l)] = true
	}
	out := make([]RelationshipSchema, 0)
	for _, r := range relations {
		if selected[strings.ToLower(r.Label)] {
			out = append(out, r)
		}
	}
	return out
}

// compactIntentVocabularyFor lists the user-language aliases of the given types.
func compactIntentVocabularyFor(types map[string]bool) string {
	names := make([]string, 0, len(types))
	for typ := range types {
		names = append(names, typ)
	}
	sort.Strings(names)
	var rows []string
	for _, typ := range names {
		if aliases := intentVocabulary[typ]; len(aliases) > 0 {
			rows = append(rows, typ+": "+strings.Join(aliases, ", "))
		}
	}
	return strings.Join(rows, "\n")
}
