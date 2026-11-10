// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"regexp"
	"sort"
	"strings"
)

var aliasPunctuation = regexp.MustCompile(`[^a-z0-9]+`)

func normalizeSchemaAlias(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = aliasPunctuation.ReplaceAllString(raw, " ")
	return strings.Join(strings.Fields(raw), " ")
}

// relationLabelAliases derives spelling and inflection variants for every
// registered relation label, then adds carefully curated semantic synonyms.
// This avoids needing to maintain a handcrafted entry for each new label.
func relationLabelAliases(label string) []string {
	aliases := []string{label, strings.ReplaceAll(label, "_", " "), strings.ReplaceAll(label, "-", " ")}
	aliases = append(aliases, relationVocabulary[strings.ToLower(label)]...)
	all := append([]string(nil), aliases...)
	for _, raw := range aliases {
		words := strings.Fields(normalizeSchemaAlias(raw))
		if len(words) == 0 {
			continue
		}

		last := words[len(words)-1]
		// A trailing preposition is not a noun to pluralize.
		switch last {
		case "to", "of", "by", "for", "with", "in", "on", "under", "over", "from", "at":
			continue
		}
		// Only a transparent English plural inflection is generated. Do not
		// stem or fuzzy-match unfamiliar words into unrelated OAM labels.
		switch {
		case strings.HasSuffix(last, "s"):
			continue
		case strings.HasSuffix(last, "y") && len(last) > 1:
			words[len(words)-1] = strings.TrimSuffix(last, "y") + "ies"
		case strings.HasSuffix(last, "ch") || strings.HasSuffix(last, "sh"):
			words[len(words)-1] = last + "es"
		default:
			words[len(words)-1] = last + "s"
		}

		all = append(all, strings.Join(words, " "))
	}

	seen := map[string]bool{}
	result := make([]string, 0, len(all))
	for _, raw := range all {
		term := normalizeSchemaAlias(raw)
		if term == "" || seen[term] {
			continue
		}

		seen[term] = true
		result = append(result, term)
	}

	return result
}

// searchableFieldAliases provides a discoverable form for every OAM
// indexed field, even if there is no hand-curated semantic expansion.
func searchableFieldAliases(field string) []string {
	aliases := []string{field, strings.ReplaceAll(field, "_", " "), strings.ReplaceAll(field, "-", " ")}
	aliases = append(aliases, searchableFieldVocabulary[field]...)
	seen := map[string]bool{}
	var result []string
	for _, a := range aliases {
		normalized := normalizeSchemaAlias(a)
		if normalized == "" || seen[normalized] {
			continue
		}

		seen[normalized] = true
		result = append(result, normalized)
	}

	return result
}

// schemaRelationAliasCandidates returns every *registered* OAM label that can
// match an explicit user phrase. An ambiguous alias produces multiple labels
// and must not be silently reduced to one.
func schemaRelationAliasCandidates(phrase string, catalog []RelationshipSchema) []string {
	needle := normalizeSchemaAlias(phrase)
	if needle == "" {
		return nil
	}

	available := map[string]bool{}
	for _, r := range catalog {
		if r.Label != "" {
			available[r.Label] = true
		}
	}

	var matched []string
	for label := range available {
		aliases := relationLabelAliases(label)
		for _, alias := range aliases {
			if normalizeSchemaAlias(alias) == needle {
				matched = append(matched, label)
				break
			}
		}
	}

	sort.Strings(matched)
	return matched
}

// The catalog vocabulary is prompt context, not an alternate ontology.
// Bounds keep local-model prompts practical even for a large schema.
func compactRelationshipVocabulary(catalog []RelationshipSchema) string {
	unique := map[string]bool{}
	for _, r := range catalog {
		unique[r.Label] = true
	}

	labels := make([]string, 0, len(unique))
	for label := range unique {
		labels = append(labels, label)
	}

	sort.Strings(labels)
	var lines []string
	for _, label := range labels {
		aliases := relationVocabulary[strings.ToLower(label)]
		if len(aliases) > 8 {
			aliases = aliases[:8]
		}
		if len(aliases) == 0 {
			continue
		}

		lines = append(lines, label+": "+strings.Join(aliases, ", "))
	}

	return strings.Join(lines, "\n")
}

func compactSearchVocabulary(selectors []AssetSearchSchema) string {
	fields := map[string]bool{}
	for _, selector := range selectors {
		for _, field := range selector.Fields {
			fields[field] = true
		}
	}

	sorted := make([]string, 0, len(fields))
	for field := range fields {
		sorted = append(sorted, field)
	}

	sort.Strings(sorted)
	var lines []string
	for _, field := range sorted {
		aliases := searchableFieldAliases(field)
		if len(aliases) > 7 {
			aliases = aliases[:7]
		}

		lines = append(lines, field+": "+strings.Join(aliases, ", "))
	}

	return strings.Join(lines, "\n")
}

func compactOperationVocabulary() string {
	intents := make([]string, 0, len(investigationOperationVocabulary))
	for k := range investigationOperationVocabulary {
		intents = append(intents, k)
	}

	sort.Strings(intents)
	var lines []string
	for _, kind := range intents {
		values := investigationOperationVocabulary[kind]
		if len(values) > 7 {
			values = values[:7]
		}

		lines = append(lines, kind+": "+strings.Join(values, ", "))
	}

	return strings.Join(lines, "\n")
}

// CuratedRelationLabels returns the OAM labels that have curated aliases,
// sorted. Tests use it to reject aliases for labels OAM does not register.
func CuratedRelationLabels() []string {
	labels := make([]string, 0, len(relationVocabulary))
	for label := range relationVocabulary {
		labels = append(labels, label)
	}

	sort.Strings(labels)
	return labels
}

// CuratedAssetTypes returns the OAM asset types that have curated aliases,
// sorted. Tests use it to reject aliases for types OAM does not register.
func CuratedAssetTypes() []string {
	types := make([]string, 0, len(intentVocabulary))
	for t := range intentVocabulary {
		types = append(types, t)
	}

	sort.Strings(types)
	return types
}
