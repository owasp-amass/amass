// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"regexp"
	"sort"
	"strings"
)

// namedRelationshipPhrase requires the user to explicitly name OAM
// relationship labels in a "through/via/using ... relationships" clause.
// Domain names, organization names, and bare words elsewhere in a question
// are not promoted into graph constraints.
var namedRelationshipPhrase = regexp.MustCompile(`(?is)\b(?:through|via|using|along)\b(.{1,140}?)\b(?:relationships|relations|edges)\b`)
var explicitlyOrderedRelations = regexp.MustCompile(`(?i)\b(?:then|followed by|in that order|in this order|in sequence)\b`)

type explicitRelationHint struct {
	Labels    []string
	Rule      string
	RawPhrase string
}

// explicitRelationLabels only discovers exact catalog label words from an
// explicit relationship phrase. It does not infer unseen edges or ownership.
func explicitRelationLabels(question string, catalog []RelationshipSchema) (explicitRelationHint, bool) {
	var hint explicitRelationHint
	matches := namedRelationshipPhrase.FindAllStringSubmatch(question, -1)
	if len(matches) != 1 {
		return hint, false
	}
	phrase := normalizeSchemaAlias(matches[0][1])
	if phrase == "" {
		return hint, false
	}

	// Longest-first token matching makes "domain registration" different
	// from bare "domain" and "official website" different from "website".
	// No alias is allowed to cross a word boundary or silently match
	// competing OAM labels. Unresolved ambiguity is handled by the planner.
	type occurrence struct {
		start, end   int
		label, alias string
	}
	occurrences := make([]occurrence, 0)
	registered := map[string]bool{}
	for _, r := range catalog {
		if r.Label != "" {
			registered[r.Label] = true
		}
	}
	for label := range registered {
		for _, raw := range relationLabelAliases(label) {
			alias := normalizeSchemaAlias(raw)
			if alias == "" {
				continue
			}
			start := 0
			for start < len(phrase) {
				n := strings.Index(phrase[start:], alias)
				if n < 0 {
					break
				}
				n += start
				end := n + len(alias)
				if (n == 0 || phrase[n-1] == ' ') && (end == len(phrase) || phrase[end] == ' ') {
					occurrences = append(occurrences, occurrence{start: n, end: end, label: label, alias: alias})
				}
				start = n + 1
			}
		}
	}
	sort.Slice(occurrences, func(i, j int) bool {
		a, b := occurrences[i], occurrences[j]
		if a.start != b.start {
			return a.start < b.start
		}
		if a.end != b.end {
			return a.end > b.end
		}
		return a.label < b.label
	})
	chosen := map[string]int{}
	for i := 0; i < len(occurrences); {
		current := occurrences[i]
		// First candidate at this position always has longest matching phrase.
		// Multiple labels for that same phrase length cannot be decided safely.
		competing := map[string]bool{current.label: true}
		for j := i + 1; j < len(occurrences); j++ {
			next := occurrences[j]
			if next.start != current.start || next.end != current.end {
				break
			}
			competing[next.label] = true
		}
		if len(competing) > 1 {
			return hint, false
		}
		chosen[current.label] = current.start
		// Ignore overlapping shorter aliases, but never silently use an
		// unrelated competing interpretation for the same matched words.
		for i < len(occurrences) && occurrences[i].start < current.end {
			i++
		}
	}
	if len(chosen) == 0 || len(chosen) > 4 {
		return hint, false
	}
	for label := range chosen {
		hint.Labels = append(hint.Labels, label)
	}
	sort.Slice(hint.Labels, func(i, j int) bool {
		a, b := chosen[hint.Labels[i]], chosen[hint.Labels[j]]
		if a == b {
			return hint.Labels[i] < hint.Labels[j]
		}
		return a < b
	})
	hint.Rule = "all"
	if explicitlyOrderedRelations.MatchString(question) {
		hint.Rule = "ordered"
	}
	hint.RawPhrase = strings.TrimSpace(matches[0][1])
	return hint, true
}

// groundedRelationshipGoal derives the shortest, exact, schema-valid
// transition sequence for explicit relation labels between the model's
// validated root and *single* requested target type. It deliberately
// supports traversing a stored edge in either direction, as guided graph
// exploration does. No database relation is invented or assumed to exist.
//
// Fail closed when more than one distinct taxonomy sequence fits the same
// root/target/labels; the model must disambiguate the semantic goal.
func groundedRelationshipGoal(hint explicitRelationHint, rootType, targetType string, catalog []RelationshipSchema) ([]GoalRelation, bool) {
	if rootType == "" || targetType == "" || len(hint.Labels) == 0 {
		return nil, false
	}
	type pathState struct {
		kind  string
		steps []GoalRelation
		seen  uint8
	}
	initial := pathState{kind: rootType}
	var found [][]GoalRelation
	distinct := map[string]bool{}
	var walk func(pathState)
	walk = func(st pathState) {
		if len(found) > 1 {
			return
		}
		if len(st.steps) == len(hint.Labels) {
			if st.kind != targetType {
				return
			}
			var key strings.Builder
			for _, r := range st.steps {
				key.WriteString(relationKey(r.SourceType, r.Label, r.RelationType, r.DestinationType))
				key.WriteByte(0)
			}
			if !distinct[key.String()] {
				distinct[key.String()] = true
				found = append(found, append([]GoalRelation(nil), st.steps...))
			}
			return
		}
		for i, label := range hint.Labels {
			if st.seen&(1<<uint(i)) != 0 {
				continue
			}
			if hint.Rule == "ordered" && i != len(st.steps) {
				continue
			}
			for _, r := range catalog {
				if !strings.EqualFold(r.Label, label) {
					continue
				}
				next := ""
				switch st.kind {
				case r.SourceType:
					next = r.DestinationType
				case r.DestinationType:
					next = r.SourceType
				default:
					continue
				}
				step := GoalRelation(r)
				nextSteps := append(append([]GoalRelation(nil), st.steps...), step)
				walk(pathState{kind: next, steps: nextSteps, seen: st.seen | (1 << uint(i))})
			}
		}
	}
	walk(initial)
	if len(found) != 1 {
		return nil, false
	}
	return found[0], true
}

// applyExplicitRelationGrounding changes ONLY relationship constraints.
// It is called after the model's subject, targets, direction and purpose
// have been validated independently. It never changes the user-selected
// asset identifier or destination types and does not fabricate OAM edges.
func applyExplicitRelationGrounding(goal InvestigationGoal, hint explicitRelationHint, catalog []RelationshipSchema) (InvestigationGoal, bool) {
	if len(goal.TargetTypes) != 1 {
		return goal, false
	}
	rels, ok := groundedRelationshipGoal(hint, goal.Subject.Type, goal.TargetTypes[0], catalog)
	if !ok {
		return goal, false
	}
	goal.Relationships = rels
	goal.PathRule = hint.Rule
	return goal, true
}
