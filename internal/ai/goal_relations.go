// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"errors"
	"fmt"
)

// GoalRelation is one exact, oriented OAM taxonomy transition.
// Direction is represented by the stored From->To relationship, regardless
// of the direction in which an investigation traverses that edge.
type GoalRelation struct {
	SourceType      string `json:"source_type"`
	Label           string `json:"label"`
	RelationType    string `json:"relation_type"`
	DestinationType string `json:"destination_type"`
}

func relationKey(src, label, relation, dst string) string {
	return src + "\x00" + label + "\x00" + relation + "\x00" + dst
}

func validGoalRelations(requirements []GoalRelation, rule string, catalog []RelationshipSchema) error {
	if len(requirements) > 8 {
		return errors.New("at most 8 relationship constraints are supported")
	}
	if rule != "" && rule != "any" && rule != "all" && rule != "ordered" {
		return fmt.Errorf("path_rule must be any, all, or ordered")
	}
	if rule != "" && len(requirements) == 0 {
		return errors.New("path_rule requires at least one relationship constraint")
	}

	allowed := map[string]bool{}
	for _, r := range catalog {
		allowed[relationKey(r.SourceType, r.Label, r.RelationType, r.DestinationType)] = true
	}

	seen := map[string]bool{}
	for _, r := range requirements {
		key := relationKey(r.SourceType, r.Label, r.RelationType, r.DestinationType)
		if !allowed[key] {
			return fmt.Errorf("relationship %s --%s/%s--> %s absent from OAM taxonomy", r.SourceType,
				r.Label, r.RelationType, r.DestinationType)
		}
		if seen[key] && rule != "ordered" {
			return errors.New("duplicate relationship constraint")
		}

		seen[key] = true
	}

	return nil
}

// pathSatisfiesGoal matches stored edge orientation and exact relation type.
// "any" permits any requested transition, "all" requires each transition,
// and "ordered" requires a subsequence, not necessarily consecutive edges.
// Unspecified constraints do not restrict any path.
func pathSatisfiesGoal(path PlanMatch, required []GoalRelation, rule string) bool {
	if len(required) == 0 {
		return true
	}
	if len(path.Edges)+1 != len(path.Nodes) {
		return false
	}

	match := func(edge Relation, r GoalRelation) bool {
		if edge.Label != r.Label || edge.Type != r.RelationType {
			return false
		}
		// Determine the actual From/To types rather than using the walk
		// direction or allowing the model to reverse an OAM assertion.
		for _, n := range path.Nodes {
			if n.ID != edge.FromID {
				continue
			}
			if n.Type != r.SourceType {
				return false
			}
			for _, dest := range path.Nodes {
				if dest.ID == edge.ToID {
					return dest.Type == r.DestinationType
				}
			}

			return false
		}

		return false
	}
	if rule == "" {
		rule = "any"
	}
	switch rule {
	case "any":
		for _, edge := range path.Edges {
			for _, r := range required {
				if match(edge, r) {
					return true
				}
			}
		}

		return false
	case "all":
		covered := make([]bool, len(required))
		for _, edge := range path.Edges {
			for j, r := range required {
				if match(edge, r) {
					covered[j] = true
				}
			}
		}
		for _, ok := range covered {
			if !ok {
				return false
			}
		}

		return true
	case "ordered":
		next := 0
		for _, edge := range path.Edges {
			if match(edge, required[next]) {
				next++
				if next == len(required) {
					return true
				}
			}
		}

		return false
	}

	return false
}
