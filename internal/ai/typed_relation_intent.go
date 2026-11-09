// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
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
var camelBoundary1 = regexp.MustCompile("([a-z0-9])([A-Z])")
var camelBoundary2 = regexp.MustCompile("([A-Z])([A-Z][a-z])")

func intentAssetAliases(kind string) []string {
	words := strings.ToLower(camelBoundary1.ReplaceAllString(camelBoundary2.ReplaceAllString(kind, "$1 $2"), "$1 $2"))
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

func intentTargetType(raw string, selector []AssetSearchSchema, relations []RelationshipSchema) (string, bool) {
	candidates := intentTypeCandidates(raw, selector, relations)
	if len(candidates) != 1 {
		return "", false
	}
	return candidates[0], true
}

func intentSubject(raw string, selectors []AssetSearchSchema) (PlanSubject, bool) {
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
	if !hostnameInQuestion.MatchString(raw) || strings.Contains(raw, "..") || strings.HasPrefix(raw, ".") || strings.HasSuffix(raw, ".") {
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
func compileCatalogHopsDirected(root, target string, hint explicitRelationHint, relations []RelationshipSchema, requiredFirstDirection string) ([]PlanHop, bool) {
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
				for _, choice := range []struct{ from, to, dir string }{{r.SourceType, r.DestinationType, "out"}, {r.DestinationType, r.SourceType, "in"}} {
					if choice.from != s.kind {
						continue
					}
					if len(s.hops) == 0 && requiredFirstDirection != "" && choice.dir != requiredFirstDirection {
						continue
					}
					hop := PlanHop{Direction: choice.dir, Label: r.Label, RelationType: r.RelationType, DestinationType: choice.to}
					visit(state{kind: choice.to, hops: append(append([]PlanHop(nil), s.hops...), hop), used: s.used | (1 << uint(i))})
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

func deterministicTypedRelationIntent(question string, catalog SchemaCatalog) (TypedRelationIntent, bool) {
	var zero TypedRelationIntent
	selectors, ok := catalog.(AssetSearchCatalog)
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
		// A generic word such as "addresses" can mean a Location or an
		// IPAddress. Only a UNIQUE catalog path may disambiguate it.
		if target != "" {
			return zero, false
		}
		target, hops = candidate, candidateHops
	}
	if target == "" {
		return zero, false
	}
	plan := TypedPlan{Subject: subject, Hops: hops}
	if err := validatePlanWithSelectors(plan, relations, fields, DefaultLimits()); err != nil {
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

// searchTypedRelationIntent executes the compiled route with server-side
// direction+label bounds. This avoids wasting the global match budget on
// unrelated URLs, DNS, TLS and other OAM graph neighbors.
func searchTypedRelationIntent(ctx context.Context, graph Graph, limits Limits, root Asset, intent TypedRelationIntent, opts AdaptiveOptions) (GraphSearchResult, error) {
	out := GraphSearchResult{Root: root, Matches: []PlanMatch{}, Mode: "typed_relation_inventory"}
	if err := limits.Validate(); err != nil {
		return out, err
	}
	bounded, ok := graph.(BoundedGraph)
	if !ok {
		return out, errors.New("bounded graph reader required")
	}
	if root.Type != intent.Goal.Subject.Type {
		return out, errors.New("resolved root type differs from intent subject")
	}
	if len(intent.Hops) < 1 || len(intent.Hops) > maxPlanHops {
		return out, errors.New("invalid typed intent hop count")
	}
	depth := opts.MaxDepth
	if depth == 0 {
		depth = limits.MaxDepth
	}
	if depth < 1 || depth > limits.MaxDepth {
		return out, errors.New("invalid depth")
	}
	if depth < len(intent.Hops) {
		out.Truncated = true
		out.Reason = "depth limit"
		out.VisitedNodes = 1
		return out, nil
	}
	maxMatches := opts.MaxMatches
	if maxMatches == 0 {
		maxMatches = min(20, limits.MaxFind)
	}
	if maxMatches < 1 || maxMatches > limits.MaxFind {
		return out, errors.New("max matches exceeds policy")
	}
	maxExpansions := opts.MaxExpansions
	if maxExpansions == 0 {
		maxExpansions = min(200, limits.MaxNodes)
	}
	if maxExpansions < 1 || maxExpansions > min(400, limits.MaxNodes*8) {
		return out, errors.New("max expansions exceeds policy")
	}
	paths := []PlanMatch{{Nodes: []Asset{root}}}
	seenNodes := map[string]bool{root.ID: true}
	seenEdges := map[string]bool{}
	seenMatches := map[string]bool{}
	for index, hop := range intent.Hops {
		previousType := root.Type
		if index > 0 {
			previousType = intent.Hops[index-1].DestinationType
		}
		diagnostic := GraphHopDiagnostic{
			Hop: index + 1, SourceType: previousType, TargetType: hop.DestinationType,
			Direction: hop.Direction, Label: hop.Label, RelationType: hop.RelationType,
			InputPaths: len(paths),
		}
		nextPaths := make([]PlanMatch, 0)
		for _, path := range paths {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if out.ExpandedPaths >= maxExpansions {
				out.Truncated = true
				out.Reason = "path expansion limit"
				break
			}
			out.ExpandedPaths++
			diagnostic.QueriedPaths++
			last := path.Nodes[len(path.Nodes)-1]
			edges, more, err := bounded.EdgesLimited(ctx, last.ID, hop.Direction, hop.Label, time.Time{}, limits.MaxPerNode)
			if err != nil {
				return out, err
			}
			diagnostic.ReturnedEdges += len(edges)
			if len(edges) > limits.MaxPerNode {
				return out, errors.New("bounded graph exceeded per-node edge policy")
			}
			if more {
				out.Truncated = true
				if out.Reason == "" {
					out.Reason = "per-node edge limit"
				}
			}
			sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
			for _, edge := range edges {
				if err := ctx.Err(); err != nil {
					return out, err
				}
				if edge.Label != hop.Label || edge.Type != hop.RelationType {
					out.SchemaRejected++
					continue
				}
				dest := ""
				if hop.Direction == "out" && edge.FromID == last.ID {
					dest = edge.ToID
				}
				if hop.Direction == "in" && edge.ToID == last.ID {
					dest = edge.FromID
				}
				if dest == "" {
					out.SchemaRejected++
					continue
				}
				cycle := false
				for _, node := range path.Nodes {
					if node.ID == dest {
						cycle = true
						break
					}
				}
				if cycle {
					continue
				}
				if !seenEdges[edge.ID] {
					if len(seenEdges) >= limits.MaxEdges {
						out.Truncated = true
						out.Reason = "edge limit"
						break
					}
					seenEdges[edge.ID] = true
				}
				if !seenNodes[dest] && len(seenNodes) >= limits.MaxNodes {
					out.Truncated = true
					out.Reason = "node limit"
					break
				}
				asset, err := graph.GetAsset(ctx, dest)
				if err != nil {
					return out, err
				}
				if asset.Type != hop.DestinationType {
					out.SchemaRejected++
					continue
				}
				seenNodes[dest] = true
				diagnostic.AcceptedEdges++
				witness := PlanMatch{
					Nodes: append(append([]Asset(nil), path.Nodes...), asset),
					Edges: append(append([]Relation(nil), path.Edges...), edge),
				}
				witness.PathID = WitnessPathID(witness)
				if index == len(intent.Hops)-1 {
					if seenMatches[asset.ID] {
						continue
					}
					seenMatches[asset.ID] = true
					out.Matches = append(out.Matches, witness)
					if len(out.Matches) >= maxMatches {
						out.Truncated = true
						out.Reason = "match limit"
						break
					}
				} else {
					// A dense multi-hop graph may admit many paths between the same
					// bounded set of nodes. Cap the frontier independently from the
					// unique edge/node budgets to avoid unbounded intermediate memory.
					if len(nextPaths) >= limits.MaxEdges {
						out.Truncated = true
						out.Reason = "intermediate path limit"
						break
					}
					nextPaths = append(nextPaths, witness)
				}
			}
			if out.Reason == "match limit" || out.Reason == "edge limit" || out.Reason == "node limit" || out.Reason == "intermediate path limit" {
				break
			}
		}
		diagnostic.Truncated = out.Truncated
		if index == len(intent.Hops)-1 {
			diagnostic.OutputPaths = len(out.Matches)
		} else {
			diagnostic.OutputPaths = len(nextPaths)
		}
		out.HopDiagnostics = append(out.HopDiagnostics, diagnostic)
		if out.Reason == "match limit" || out.Reason == "edge limit" || out.Reason == "node limit" || out.Reason == "intermediate path limit" || out.Reason == "path expansion limit" {
			break
		}
		// Do not issue empty subsequent hops. Preserve the first failing hop
		// and keep the query complete when no limit or repository error occurred.
		if len(nextPaths) == 0 && index < len(intent.Hops)-1 {
			break
		}
		paths = nextPaths
	}
	out.VisitedNodes = len(seenNodes)
	out.VisitedEdges = len(seenEdges)
	out.Exhausted = !out.Truncated
	sort.Slice(out.Matches, func(i, j int) bool {
		a, b := out.Matches[i], out.Matches[j]
		x, y := a.Nodes[len(a.Nodes)-1], b.Nodes[len(b.Nodes)-1]
		if x.Key == y.Key {
			return a.PathID < b.PathID
		}
		return x.Key < y.Key
	})
	return out, nil
}

func typedRelationAnswer(root Asset, intent TypedRelationIntent, paths []PlanMatch, truncated bool, reason string) string {
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

// typedRelationEmptyExplanation identifies the FIRST missing typed hop rather
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
