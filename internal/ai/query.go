// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"errors"
	"fmt"
	"strings"
)

// QueryVersion is the current Query schema version.
const QueryVersion = 1

// Traversal strategies a Query can request.
const (
	// TraversalExplore searches every schema-valid OAM transition from the
	// root up to the limits, optionally constrained by Relationships and
	// PathRule, and lets the model choose among witnessed paths.
	TraversalExplore = "explore"
	// TraversalRoute follows exactly the listed Hops, in order.
	TraversalRoute = "route"
	// TraversalHierarchy descends the FQDN "node" hierarchy below the root.
	TraversalHierarchy = "hierarchy"
)

// Query compilers recorded in Query.Source.
const (
	SourceFQDNHierarchy        = "fqdn_hierarchy"
	SourceTypedRelation        = "typed_relation"
	SourceOrganizationRelation = "organization_relation"
	SourceModelGoal            = "model_goal"
	SourceCaller               = "caller"
	SourceThirdPartyLens       = "third_party_lens"
)

// Query is the single, model-independent intermediate representation of a
// read-only OAM investigation. Every route into an investigation (the narrow
// deterministic question compilers, the model goal planner, and structured
// callers such as the CLI or MCP) produces a Query. ValidateQuery checks it
// once against the authoritative OAM catalog, and Agent.AskQuery executes it.
//
// A Query describes what to retrieve, never a fact: executing it only reads
// stored OAM assets and relations.
type Query struct {
	Version int `json:"version"`
	// Question is the user's wording, when there is one. Explore queries use
	// it to guide path selection; it never changes what is valid to read.
	Question string      `json:"question,omitempty"`
	Subject  PlanSubject `json:"subject"`
	// Traversal is explore, route or hierarchy.
	Traversal string `json:"traversal"`
	// TargetTypes are the OAM asset types the answer is about. Empty means
	// any type (explore only).
	TargetTypes []string `json:"target_types,omitempty"`
	// Direction is the stored edge direction for explore: both, in or out.
	Direction string `json:"direction"`
	// Purpose is connected or ultimate_parent (explore only).
	Purpose string `json:"purpose"`
	// Relationships constrain explore paths according to PathRule. For a
	// route they are the catalog transitions behind each hop.
	Relationships []GoalRelation `json:"relationships,omitempty"`
	PathRule      string         `json:"path_rule,omitempty"`
	// Hops is the exact route for TraversalRoute.
	Hops []PlanHop `json:"hops,omitempty"`
	// ExcludeRoot omits the root asset from a hierarchy inventory, as when a
	// user asks for subdomains rather than FQDNs.
	ExcludeRoot bool `json:"exclude_root,omitempty"`
	// Lens, when set, answers a fixed question about the subject from the
	// relationship attribution table instead of a traversal: third_party
	// lists the outside vendors its controlled assets use, and controlled
	// lists the assets (of TargetTypes, when set) attributed to it. Lenses
	// use the explore traversal and need no model.
	Lens string `json:"lens,omitempty"`
	// Source names the compiler that produced the Query.
	Source string `json:"source"`
}

// Goal returns the InvestigationGoal view of q used by explore search and
// path evaluation.
func (q Query) Goal() InvestigationGoal {
	return InvestigationGoal{
		Subject:       q.Subject,
		TargetTypes:   append([]string(nil), q.TargetTypes...),
		Direction:     q.Direction,
		Purpose:       q.Purpose,
		Relationships: append([]GoalRelation(nil), q.Relationships...),
		PathRule:      q.PathRule,
	}
}

// Deterministic reports whether q can be executed and answered without a
// model: route and hierarchy answers list every witnessed destination.
func (q Query) Deterministic() bool {
	return q.Traversal == TraversalRoute || q.Traversal == TraversalHierarchy || q.Lens != ""
}

// Describe renders q as one line of plain English for traces, prompts and
// callers that supplied a structured Query without a question.
func (q Query) Describe() string {
	subject := formatPlanSubject(q.Subject)
	targets := "any OAM asset type"
	if len(q.TargetTypes) > 0 {
		targets = strings.Join(q.TargetTypes, ", ")
	}
	switch q.Lens {
	case LensThirdParty:
		return fmt.Sprintf("List the third-party vendors used by the assets %s controls.", subject)
	case LensControlled:
		return fmt.Sprintf("List the %s assets controlled by %s.", targets, subject)
	}

	switch q.Traversal {
	case TraversalHierarchy:
		what := "FQDNs"
		if q.ExcludeRoot {
			what = "subdomains"
		}

		return fmt.Sprintf("List %s below %s through the stored FQDN node hierarchy.", what, subject)
	case TraversalRoute:
		steps := make([]string, 0, len(q.Hops))
		for _, h := range q.Hops {
			steps = append(steps, fmt.Sprintf("%s %s to %s", h.Direction, h.Label, h.DestinationType))
		}

		return fmt.Sprintf("List %s reached from %s by following %s.", targets, subject, strings.Join(steps, ", then "))
	default:
		if q.Purpose == "ultimate_parent" {
			return fmt.Sprintf("Find the highest documented parent Organization of %s.", subject)
		}

		desc := fmt.Sprintf("Find %s connected to %s", targets, subject)
		if len(q.Relationships) > 0 {
			labels := make([]string, 0, len(q.Relationships))
			for _, r := range q.Relationships {
				labels = append(labels, r.Label)
			}

			desc += fmt.Sprintf(" via %s relationships (%s)", strings.Join(labels, ", "), q.PathRule)
		}

		return desc + "."
	}
}

// QueryFromGoal wraps an explore goal as a Query.
func QueryFromGoal(goal InvestigationGoal, question, source string) Query {
	return Query{
		Version:       QueryVersion,
		Question:      question,
		Subject:       goal.Subject,
		Traversal:     TraversalExplore,
		TargetTypes:   append([]string(nil), goal.TargetTypes...),
		Direction:     goal.Direction,
		Purpose:       goal.Purpose,
		Relationships: append([]GoalRelation(nil), goal.Relationships...),
		PathRule:      goal.PathRule,
		Source:        source,
	}
}

// ValidateQuery accepts only queries whose subject selector, types,
// relationships and hops all exist in the OAM catalog, and whose traversal
// fields are consistent. It never touches the Asset Database.
func ValidateQuery(q Query, catalog []RelationshipSchema, selectors []AssetSearchSchema, limits Limits) error {
	if q.Version != QueryVersion {
		return fmt.Errorf("unsupported query version %d (want %d)", q.Version, QueryVersion)
	}
	if err := validateGoal(q.Goal(), catalog, selectors); err != nil {
		return err
	}
	switch q.Traversal {
	case TraversalExplore:
		if len(q.Hops) != 0 {
			return errors.New("explore queries cannot specify hops; use the route traversal")
		}
		if q.ExcludeRoot {
			return errors.New("exclude_root applies only to the hierarchy traversal")
		}
	case TraversalRoute:
		if q.Purpose != "connected" {
			return errors.New("route queries must use purpose connected")
		}
		if q.ExcludeRoot {
			return errors.New("exclude_root applies only to the hierarchy traversal")
		}
		if err := validatePlanWithSelectors(TypedPlan{Subject: q.Subject, Hops: q.Hops}, catalog, selectors,
			limits); err != nil {
			return err
		}

		last := q.Hops[len(q.Hops)-1].DestinationType
		if len(q.TargetTypes) != 1 || q.TargetTypes[0] != last {
			return fmt.Errorf("route target_types must be exactly the final hop type %s", last)
		}

		want, err := routeRelationships(q.Subject.Type, q.Hops, catalog)
		if err != nil {
			return err
		}
		if len(q.Relationships) != 0 && (q.PathRule != "ordered" || !sameRelations(q.Relationships, want)) {
			return errors.New("route relationships must match its hops in order")
		}
	case TraversalHierarchy:
		if q.Subject.Type != "FQDN" || q.Subject.UsesOrganizationResolution() {
			return errors.New("hierarchy queries must start from an FQDN")
		}
		if len(q.Hops) != 0 || q.Purpose != "connected" || q.Direction != "out" ||
			len(q.TargetTypes) != 1 || q.TargetTypes[0] != "FQDN" {
			return errors.New("hierarchy queries descend out to FQDN targets with purpose connected and no hops")
		}

		node := GoalRelation{SourceType: "FQDN", Label: "node", RelationType: "SimpleRelation", DestinationType: "FQDN"}
		if len(q.Relationships) != 1 || q.Relationships[0] != node {
			return errors.New("hierarchy queries use exactly the FQDN node relationship")
		}
	default:
		return fmt.Errorf("traversal must be %s, %s or %s", TraversalExplore, TraversalRoute, TraversalHierarchy)
	}
	switch q.Lens {
	case "":
	case LensThirdParty, LensControlled:
		if q.Traversal != TraversalExplore || len(q.Hops) != 0 {
			return errors.New("lens queries use the explore traversal without hops")
		}
		if q.Subject.Type != "Organization" && q.Subject.Type != "FQDN" {
			return fmt.Errorf("the %s lens starts from an Organization or FQDN", q.Lens)
		}
	default:
		return fmt.Errorf("unknown lens %q", q.Lens)
	}
	switch q.Source {
	case SourceThirdPartyLens, SourceFQDNHierarchy, SourceTypedRelation, SourceOrganizationRelation,
		SourceModelGoal, SourceCaller:
	default:
		return fmt.Errorf("unknown query source %q", q.Source)
	}

	return nil
}

// routeRelationships returns the catalog transition behind each hop.
func routeRelationships(subjectType string, hops []PlanHop, catalog []RelationshipSchema) ([]GoalRelation, error) {
	out := make([]GoalRelation, 0, len(hops))
	current := subjectType
	for i, h := range hops {
		found := false
		for _, r := range catalog {
			if r.Label != h.Label || r.RelationType != h.RelationType {
				continue
			}
			if (h.Direction == "out" && r.SourceType == current && r.DestinationType == h.DestinationType) ||
				(h.Direction == "in" && r.DestinationType == current && r.SourceType == h.DestinationType) {
				out = append(out, GoalRelation(r))
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("hop %d has no OAM catalog transition", i+1)
		}

		current = h.DestinationType
	}

	return out, nil
}

func sameRelations(a, b []GoalRelation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
