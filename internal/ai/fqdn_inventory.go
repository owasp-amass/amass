// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Only unambiguous FQDN inventory questions qualify for this fast path.
// "Associated" in this narrow mode means descending stored OAM "node"
// edges, not DNS-record association, organization attribution or validation.
// Ambiguous questions still fall through to the model planner.
var fqdnInventoryQuestion = regexp.MustCompile(`(?i)^\s*(?:(?:which|what|list|show)(?:\s+(?:all|the))?\s+(?:fqdn|fqdns|fully qualified domain name|fully qualified domain names|hostname|hostnames|dns names?|subdomain|subdomains|subdomain names?)(?:\s+assets)?(?:\s+(?:are|were))?(?:\s+(?:associated|connected|related)\s+with|\s+(?:under|beneath|within|for|of))|(?:list|show)\s+(?:all\s+)?(?:subdomains|subdomain names|hostnames)\s+(?:of|under|for))\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:\s*\?)?\s*$`)

// subdomainInventoryQuestion accepts the everyday wordings of a subdomain
// listing, such as "what are all the subdomains within example.com?" or
// "list the hostnames in example.com's DNS namespace". The question must
// name exactly one domain and nothing else.
var subdomainInventoryQuestion = regexp.MustCompile(`(?i)^\s*(?:(?:what|which)(?:\s+(?:are|were))?\s+|(?:list|show|give me|find|get|enumerate|name)\s+)?(?:all\s+)?(?:of\s+)?(?:the\s+)?(?:known\s+|discovered\s+)?(?:subdomains?|subdomain names|hostnames|fqdns|dns names)(?:\s+(?:that\s+)?(?:are|were|exist))?\s+(?:in|within|under|beneath|below|of|for|on)\s+(?:the\s+)?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:'s)?(?:\s+(?:dns\s+)?(?:namespace|domain|zone))?\s*\??\s*$`)

func fqdnInventoryHost(question string) (string, bool) {
	for _, re := range []*regexp.Regexp{fqdnInventoryQuestion, subdomainInventoryQuestion} {
		if m := re.FindStringSubmatch(question); len(m) == 2 {
			return strings.ToLower(m[1]), true
		}
	}

	return "", false
}

func deterministicFQDNInventoryGoal(question string, catalog SchemaCatalog) (InvestigationGoal, bool) {
	var zero InvestigationGoal
	host, ok := fqdnInventoryHost(question)
	if !ok {
		return zero, false
	}

	if strings.Contains(host, "..") || strings.Contains(host, ".-") || strings.Contains(host,
		"-.") || strings.HasSuffix(host, ".") {
		return zero, false
	}

	selector, ok := catalog.(AssetSearchCatalog)
	if !ok {
		return zero, false
	}

	foundField, foundNode := false, false
	for _, s := range selector.SearchFields() {
		if s.Type != "FQDN" {
			continue
		}
		for _, field := range s.Fields {
			if field == "name" {
				foundField = true
			}
		}
	}
	for _, r := range catalog.Relations() {
		if r.SourceType == "FQDN" && r.DestinationType == "FQDN" && r.Label == "node" &&
			r.RelationType == "SimpleRelation" {
			foundNode = true
		}
	}
	if !foundField || !foundNode {
		return zero, false
	}

	goal := InvestigationGoal{
		Subject:     PlanSubject{Type: "FQDN", Field: "name", Value: host},
		TargetTypes: []string{"FQDN"}, Direction: "out", Purpose: "connected",
		Relationships: []GoalRelation{
			{SourceType: "FQDN", DestinationType: "FQDN", Label: "node", RelationType: "SimpleRelation"},
		},
		PathRule: "all",
	}
	if err := validateGoal(goal, catalog.Relations(), selector.SearchFields()); err != nil {
		return zero, false
	}

	return goal, true
}

// searchFQDNInventory is deliberately bounded and schema-grounded.
// Traversing only outgoing FQDN --node/SimpleRelation--> FQDN avoids
// spending match limits on unrelated DNS, URLs, IPs and organizations.
// A suffix check ensures a malformed stored relation cannot pull an
// unrelated FQDN into the requested scope.
func searchFQDNInventory(ctx context.Context, graph Graph, limits Limits, root Asset, opts AdaptiveOptions) (GraphSearchResult, error) {
	out := GraphSearchResult{Root: root, Matches: []PlanMatch{}, Mode: "fqdn_inventory"}
	if err := limits.Validate(); err != nil {
		return out, err
	}
	if root.Type != "FQDN" {
		return out, errors.New("FQDN inventory requires FQDN root")
	}

	bounded, ok := graph.(BoundedGraph)
	if !ok {
		return out, errors.New("bounded graph reader required")
	}

	// An inventory never reaches the model, so it is bounded by its own
	// name limit rather than the model-context node, edge and per-node limits.
	depth, maxMatches, maxExpansions := opts.MaxDepth, inventoryLimit(opts), opts.MaxExpansions
	if depth == 0 {
		depth = limits.MaxDepth
	}
	if maxExpansions == 0 {
		maxExpansions = maxMatches + 1
	}
	if depth < 1 || depth > limits.MaxDepth {
		return out, errors.New("depth exceeds policy")
	}
	if maxMatches < 1 || maxMatches > MaxInventoryNames {
		return out, fmt.Errorf("inventory limit must be 1..%d", MaxInventoryNames)
	}
	if maxExpansions < 1 || maxExpansions > maxMatches+1 {
		return out, errors.New("max expansions exceeds inventory policy")
	}

	// A name's children are read in one bounded read, or a page at a time
	// up to the inventory's own limit when the graph pages, so a domain with
	// more direct subdomains than one read returns is still listed in full.
	perNode := min(maxMatches+1, MaxEdgeRead)
	_, paged := graph.(PagedGraph)
	if paged {
		perNode = maxMatches + 1
	}
	maxEdges := 4 * (maxMatches + 1)

	type queued struct {
		asset Asset
		path  PlanMatch
	}
	initial := PlanMatch{Nodes: []Asset{root}, Edges: []Relation{}}
	initial.PathID = WitnessPathID(initial)
	pending := []queued{{asset: root, path: initial}}
	seen := map[string]bool{root.ID: true}
	seenEdges := map[string]bool{}
	rootName := strings.ToLower(strings.TrimSuffix(root.Key, "."))
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if out.ExpandedPaths >= maxExpansions {
			out.Truncated = true
			out.Reason = "path expansion limit"
			break
		}

		current := pending[0]
		pending = pending[1:]
		if len(current.path.Edges) >= depth {
			continue
		}

		out.ExpandedPaths++
		var edges []Relation
		var more bool
		var err error
		if paged {
			edges, more, err = readEdges(ctx, graph, current.asset.ID, "out", "node", perNode,
				func() bool { return true })
		} else {
			edges, more, err = bounded.EdgesLimited(ctx, current.asset.ID, "out", "node", time.Time{}, perNode)
		}
		if err != nil {
			return out, err
		}
		if len(edges) > perNode {
			return out, errors.New("bounded graph returned too many node edges")
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
			if edge.FromID != current.asset.ID || edge.ToID == "" || edge.Type != "SimpleRelation" ||
				edge.Label != "node" {
				out.SchemaRejected++
				continue
			}
			if !seenEdges[edge.ID] {
				if len(seenEdges) >= maxEdges {
					out.Truncated = true
					out.Reason = "edge limit"
					break
				}

				seenEdges[edge.ID] = true
			}
			if seen[edge.ToID] {
				continue
			}
			if len(seen) > maxMatches {
				out.Truncated = true
				out.Reason = "node limit"
				break
			}

			next, err := graph.GetAsset(ctx, edge.ToID)
			if err != nil {
				return out, err
			}

			nextName := strings.ToLower(strings.TrimSuffix(next.Key, "."))
			if next.Type != "FQDN" || !strings.HasSuffix(nextName, "."+rootName) {
				out.SchemaRejected++
				continue
			}

			seen[next.ID] = true
			path := PlanMatch{
				Nodes: append(append([]Asset(nil), current.path.Nodes...), next),
				Edges: append(append([]Relation(nil), current.path.Edges...), edge),
			}
			path.PathID = WitnessPathID(path)
			out.Matches = append(out.Matches, path)
			pending = append(pending, queued{asset: next, path: path})
			if len(out.Matches) >= maxMatches {
				out.Truncated = true
				out.Reason = "match limit"
				break
			}
		}
		if out.Reason == "match limit" || out.Reason == "node limit" || out.Reason == "edge limit" {
			break
		}
	}

	out.VisitedNodes = len(seen)
	out.VisitedEdges = len(seenEdges)
	if out.SchemaRejected > 0 && !out.Truncated {
		out.Truncated = true
		out.Reason = "stored edge absent from FQDN node taxonomy/scope"
	}

	out.Exhausted = !out.Truncated
	// Make names deterministic independent of database edge identifier order.
	sort.Slice(out.Matches, func(i, j int) bool {
		a := out.Matches[i].Nodes[len(out.Matches[i].Nodes)-1].Key
		b := out.Matches[j].Nodes[len(out.Matches[j].Nodes)-1].Key
		if a == b {
			return out.Matches[i].PathID < out.Matches[j].PathID
		}

		return a < b
	})
	return out, nil
}

func fqdnInventoryAnswerScoped(root Asset, paths []PlanMatch, truncated bool, reason string, subdomainsOnly bool) string {
	names := make([]string, 0, len(paths)+1)
	if !subdomainsOnly {
		names = append(names, root.Key)
	}

	seen := map[string]bool{root.ID: true}
	for _, path := range paths {
		if len(path.Nodes) == 0 {
			continue
		}

		last := path.Nodes[len(path.Nodes)-1]
		if seen[last.ID] {
			continue
		}

		seen[last.ID] = true
		names = append(names, last.Key)
	}

	sort.Strings(names)
	description := "FQDN asset(s)"
	if subdomainsOnly {
		description = "subdomain FQDN asset(s)"
	}

	answer := fmt.Sprintf("Found %d %s in the stored OAM node hierarchy for %s:\n%s", len(names),
		description, root.Key, strings.Join(names, "\n"))
	answer += "\nThese are stored FQDN asset associations, not proof of current DNS resolution or ownership."
	if truncated {
		answer += " Results are partial (search truncated: " + reason + "); additional names may exist."
	}

	return answer
}

var subdomainInventoryLanguage = regexp.MustCompile(`(?i)\bsubdomains?\b|\bdns\s+namespace\b`)

// Inventory limits. An inventory is listed by Go and never sent to the
// model, so it can return far more names than a model-evaluated search.
const (
	DefaultInventoryNames = 1000
	MaxInventoryNames     = 10000
)

// inventoryLimit is MaxInventory when set, then an explicit MaxMatches,
// then DefaultInventoryNames.
func inventoryLimit(opts AdaptiveOptions) int {
	if opts.MaxInventory > 0 {
		return opts.MaxInventory
	}
	if opts.MaxMatches > 0 {
		return opts.MaxMatches
	}

	return DefaultInventoryNames
}

// promoteHierarchyGoal turns a goal that starts at an FQDN, asks for FQDNs
// and follows only the FQDN node relationship into the hierarchy
// traversal, so it is answered by the bounded inventory walk instead of
// model path selection. It looks only at the goal's structure.
func promoteHierarchyGoal(q *Query) bool {
	node := GoalRelation{SourceType: "FQDN", Label: "node", RelationType: "SimpleRelation", DestinationType: "FQDN"}
	if q.Subject.Type != "FQDN" || q.Subject.UsesOrganizationResolution() || len(q.Hops) != 0 ||
		len(q.TargetTypes) != 1 || q.TargetTypes[0] != "FQDN" || len(q.Relationships) == 0 {
		return false
	}
	for _, rel := range q.Relationships {
		if rel != node {
			return false
		}
	}

	hierarchyQuery(q)
	return true
}

// hierarchyQuery converts q, which starts at an FQDN, into the hierarchy
// traversal. A question that says "subdomains" omits the root itself.
func hierarchyQuery(q *Query) {
	q.Traversal = TraversalHierarchy
	q.TargetTypes = []string{"FQDN"}
	q.Direction = "out"
	q.Purpose = "connected"
	q.Relationships = []GoalRelation{
		{SourceType: "FQDN", Label: "node", RelationType: "SimpleRelation", DestinationType: "FQDN"},
	}
	q.PathRule = "all"
	q.ExcludeRoot = isSubdomainInventoryQuestion(q.Question)
}

func isSubdomainInventoryQuestion(question string) bool {
	return subdomainInventoryLanguage.MatchString(question)
}
