// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// TypedRelationIntent compiles an unambiguous, user-named OAM relationship
// query into exact, catalog-validated hops. It is not a guess about ownership.
// More complex/ambiguous language is left to the semantic planner.
type TypedRelationIntent struct {
	Goal InvestigationGoal
	Hops []PlanHop
}

var typedRelationQuestion = regexp.MustCompile(`(?i)^\s*(?:which|what|list|show)(?:\s+(?:all|the))?\s+(.+?)\s+(?:are\s+)?(?:associated|connected|related|linked)\s+(?:with|to)\s+(.+?)\s+(?:through|via|using)\s+(.+?)\s+(?:relationships|relations|edges)\s*\??\s*$`)
var typedSubject = regexp.MustCompile("^([A-Za-z][A-Za-z0-9]*):([a-zA-Z][a-zA-Z0-9_]+)=(.+)$")

func intentAssetAliases(kind string) []string {
	words := strings.ToLower(graph.CamelBoundary1.ReplaceAllString(graph.CamelBoundary2.ReplaceAllString(kind, "$1 $2"), "$1 $2"))
	candidates := []string{strings.ToLower(kind), words}
	for _, base := range []string{strings.ToLower(kind), words} {
		if strings.HasSuffix(base, "y") {
			candidates = append(candidates, strings.TrimSuffix(base, "y")+"ies")
		} else {
			candidates = append(candidates, base+"s")
		}
	}

	candidates = append(candidates, intentVocabulary[kind]...)
	if kind == "FQDN" {
		candidates = append(candidates, "fqdn", "fqdns", "fully qualified domain name", "fully qualified domain names")
	}

	unique := map[string]bool{}
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		normalized := normalizeIntentTerm(candidate)
		if normalized == "" || unique[normalized] {
			continue
		}

		unique[normalized] = true
		out = append(out, normalized)
	}

	return out
}

func intentTargetType(raw string, selector []graph.AssetSearchSchema, relations []graph.RelationshipSchema) (string, bool) {
	candidates := intentTypeCandidates(raw, selector, relations)
	if len(candidates) != 1 {
		return "", false
	}

	return candidates[0], true
}

func intentSubject(raw string, selectors []graph.AssetSearchSchema) (PlanSubject, bool) {
	raw = strings.TrimSpace(raw)
	if m := typedSubject.FindStringSubmatch(raw); len(m) == 4 {
		value := strings.TrimSpace(m[3])
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}

		subject := PlanSubject{Type: m[1], Field: m[2], Value: value}
		if err := subject.AssetSelector().Validate(selectors); err == nil {
			return subject, true
		}

		return PlanSubject{}, false
	}
	if strings.ContainsAny(raw, " \t\n\r") || strings.Contains(raw, "@") {
		return PlanSubject{}, false
	}
	// URL and IP parsers are exact; do not turn a partial URL into an FQDN.
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || parsed.User != nil {
			return PlanSubject{}, false
		}

		subject := PlanSubject{Type: "URL", Field: "url", Value: raw}
		if subject.AssetSelector().Validate(selectors) == nil {
			return subject, true
		}

		return PlanSubject{}, false
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		subject := PlanSubject{Type: "IPAddress", Field: "address", Value: ip.String()}
		if subject.AssetSelector().Validate(selectors) == nil {
			return subject, true
		}

		return PlanSubject{}, false
	}
	if !hostnameInQuestion.MatchString(raw) || strings.Contains(raw, "..") || strings.HasPrefix(raw,
		".") || strings.HasSuffix(raw, ".") {
		return PlanSubject{}, false
	}
	if matches := hostnameInQuestion.FindAllStringSubmatch(raw, -1); len(matches) != 1 || matches[0][1] != raw {
		return PlanSubject{}, false
	}

	subject := PlanSubject{Type: "FQDN", Field: "name", Value: strings.ToLower(raw)}
	if subject.AssetSelector().Validate(selectors) == nil {
		return subject, true
	}

	return PlanSubject{}, false
}

// Only an explicitly requested hierarchy is allowed to constrain edge
// direction before compiling the route. Other relations stay ambiguous if
// both orientations are valid from the requested source and destination.
func compileCatalogHopsDirected(root, target string, hint explicitRelationHint, relations []graph.RelationshipSchema, requiredFirstDirection string) ([]PlanHop, bool) {
	if len(hint.Labels) == 0 || len(hint.Labels) > maxPlanHops {
		return nil, false
	}

	type state struct {
		kind string
		hops []PlanHop
		used uint8
	}
	unique := map[string][]PlanHop{}
	var visit func(state)
	visit = func(s state) {
		if len(unique) > 1 {
			return
		}
		if len(s.hops) == len(hint.Labels) {
			if s.kind != target {
				return
			}

			var signature strings.Builder
			for _, hop := range s.hops {
				signature.WriteString(hop.Direction)
				signature.WriteByte(0)
				signature.WriteString(hop.Label)
				signature.WriteByte(0)
				signature.WriteString(hop.RelationType)
				signature.WriteByte(0)
				signature.WriteString(hop.DestinationType)
				signature.WriteByte(0)
			}

			unique[signature.String()] = append([]PlanHop(nil), s.hops...)
			return
		}
		for i, label := range hint.Labels {
			if s.used&(1<<uint(i)) != 0 {
				continue
			}
			if hint.Rule == "ordered" && i != len(s.hops) {
				continue
			}
			for _, r := range relations {
				if !strings.EqualFold(r.Label, label) {
					continue
				}
				for _, choice := range []struct{ from, to, dir string }{
					{r.SourceType, r.DestinationType, "out"},
					{r.DestinationType, r.SourceType, "in"},
				} {
					if choice.from != s.kind {
						continue
					}
					if len(s.hops) == 0 && requiredFirstDirection != "" && choice.dir != requiredFirstDirection {
						continue
					}

					hop := PlanHop{
						Direction:       choice.dir,
						Label:           r.Label,
						RelationType:    r.RelationType,
						DestinationType: choice.to,
					}
					visit(state{kind: choice.to, hops: append(append([]PlanHop(nil),
						s.hops...), hop), used: s.used | (1 << uint(i))})
				}
			}
		}
	}
	visit(state{kind: root})
	if len(unique) != 1 {
		return nil, false
	}
	for _, hops := range unique {
		return hops, true
	}

	return nil, false
}

func deterministicTypedRelationIntent(question string, catalog graph.SchemaCatalog) (TypedRelationIntent, bool) {
	var zero TypedRelationIntent
	selectors, ok := catalog.(graph.AssetSearchCatalog)
	if !ok {
		return zero, false
	}

	matches := typedRelationQuestion.FindStringSubmatch(question)
	if len(matches) != 4 {
		return zero, false
	}

	relations, fields := catalog.Relations(), selectors.SearchFields()
	candidates := intentTypeCandidates(matches[1], fields, relations)
	if len(candidates) == 0 {
		return zero, false
	}

	subject, ok := intentSubject(matches[2], fields)
	if !ok {
		return zero, false
	}

	hint, ok := explicitRelationLabels(question, relations)
	if !ok || len(hint.Labels) > maxPlanHops {
		return zero, false
	}

	var target string
	var hops []PlanHop
	for _, candidate := range candidates {
		direction := ""
		if subdomainTerm(matches[1]) {
			direction = "out"
		}

		candidateHops, valid := compileCatalogHopsDirected(subject.Type, candidate, hint, relations, direction)
		if !valid {
			continue
		}
		if subdomainTerm(matches[1]) {
			// "Subdomain" is not a generic FQDN alias: it additionally asserts
			// a hostname hierarchy. Do not substitute a DNS or URL association.
			if subject.Type != "FQDN" || len(candidateHops) != 1 ||
				candidateHops[0].Direction != "out" || candidateHops[0].Label != "node" {
				continue
			}
		}
		// A generic word such as "addresses" can mean a StreetAddress or an
		// IPAddress. Only a unique catalog path may disambiguate it.
		if target != "" {
			return zero, false
		}

		target, hops = candidate, candidateHops
	}
	if target == "" {
		return zero, false
	}

	plan := TypedPlan{Subject: subject, Hops: hops}
	if err := validatePlanWithSelectors(plan, relations, fields, graph.DefaultLimits()); err != nil {
		return zero, false
	}

	required := make([]GoalRelation, 0, len(hops))
	current := subject.Type
	for _, h := range hops {
		for _, r := range relations {
			if r.Label != h.Label || r.RelationType != h.RelationType {
				continue
			}
			if (h.Direction == "out" && r.SourceType == current && r.DestinationType == h.DestinationType) ||
				(h.Direction == "in" && r.DestinationType == current && r.SourceType == h.DestinationType) {
				required = append(required, GoalRelation(r))
				break
			}
		}

		current = h.DestinationType
	}
	if len(required) != len(hops) {
		return zero, false
	}

	goal := InvestigationGoal{Subject: subject, TargetTypes: []string{target}, Direction: "both",
		Purpose: "connected", Relationships: required, PathRule: "ordered"}
	if err := validateGoal(goal, relations, fields); err != nil {
		return zero, false
	}

	return TypedRelationIntent{Goal: goal, Hops: hops}, true
}

func typedRelationAnswer(root graph.Asset, intent TypedRelationIntent, paths []graph.PlanMatch, truncated bool, reason string) string {
	target := ""
	if len(intent.Goal.TargetTypes) > 0 {
		target = intent.Goal.TargetTypes[0]
	}

	names := make([]string, 0, len(paths))
	for _, path := range paths {
		if len(path.Nodes) > 0 {
			names = append(names, path.Nodes[len(path.Nodes)-1].Key)
		}
	}

	sort.Strings(names)
	labels := make([]string, 0, len(intent.Hops))
	for _, hop := range intent.Hops {
		labels = append(labels, hop.Direction+":"+hop.Label+"/"+hop.RelationType)
	}

	answer := fmt.Sprintf("Found %d %s asset(s) connected to %s through stored OAM relationship path [%s]:",
		len(names), target, root.Key, strings.Join(labels, " -> "))
	if len(names) > 0 {
		answer += "\n" + strings.Join(names, "\n")
	}

	answer += "\nThese are stored graph associations, not independently verified ownership or current reachability."
	if truncated {
		answer += " Results are partial (search truncated: " + reason + "); additional matches may exist."
	}

	return answer
}

// typedRelationEmptyExplanation identifies the first missing typed hop rather
// than treating an unexecuted downstream relationship as disproved. This
// only describes edges returned by the bounded OAM reader, never global
// absence or independent ownership evidence.
func typedRelationEmptyExplanation(search GraphSearchResult, intent TypedRelationIntent) string {
	if len(search.Matches) != 0 || len(search.HopDiagnostics) == 0 {
		return ""
	}
	for _, hop := range search.HopDiagnostics {
		if hop.OutputPaths > 0 {
			continue
		}

		description := fmt.Sprintf(" The first empty relationship hop was %d (%s --%s:%s/%s--> %s).",
			hop.Hop, hop.SourceType, hop.Direction, hop.Label, hop.RelationType, hop.TargetType)
		if hop.ReturnedEdges == 0 {
			description += fmt.Sprintf(" The bounded graph reader returned no matching edges for %d queried path(s).", hop.QueriedPaths)
		} else {
			description += fmt.Sprintf(" The graph reader returned %d edge(s), but none produced an eligible destination; %d were accepted before path constraints.", hop.ReturnedEdges, hop.AcceptedEdges)
		}
		if len(search.HopDiagnostics) < len(intent.Hops) {
			description += fmt.Sprintf(" The %d subsequent hop(s) were not evaluated because there were no candidates to continue from.", len(intent.Hops)-len(search.HopDiagnostics))
		}

		description += " This does not prove the target assets or other OAM relationship paths are absent."
		return description
	}

	return ""
}
