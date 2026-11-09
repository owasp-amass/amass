// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
)

// CompileQuestion turns a natural-language question into a validated Query.
// Narrow, explicit wordings are compiled deterministically, in order:
// FQDN/subdomain inventories, typed "via <labels> relationships" questions,
// and explicit Organization relationship questions. Anything else goes to
// the model goal planner. Every result passes ValidateQuery before return.
// CompileQuestion never touches the Asset Database.
func (a Agent) CompileQuestion(ctx context.Context, question string) (Query, error) {
	var zero Query
	if a.Runner.Catalog == nil {
		return zero, errors.New("OAM schema catalog is required")
	}

	q, ok := compileDeterministicQuestion(question, a.Runner.Catalog)
	if !ok {
		if a.Model == nil {
			return zero, errors.New("question needs the model planner, but no model is configured")
		}

		goal, err := a.planGoal(ctx, question)
		if err != nil {
			return zero, err
		}

		q = QueryFromGoal(goal, question, SourceModelGoal)
		promoteHierarchyGoal(&q)
	}

	var selectors []AssetSearchSchema
	if c, ok := a.Runner.Catalog.(AssetSearchCatalog); ok {
		selectors = c.SearchFields()
	}
	if err := ValidateQuery(q, a.Runner.Catalog.Relations(), selectors, a.Runner.Limits); err != nil {
		return zero, fmt.Errorf("compiled query is invalid: %w", err)
	}

	return q, nil
}

// compileDeterministicQuestion runs the model-free compilers. It returns
// false when no compiler recognises the wording.
func compileDeterministicQuestion(question string, catalog SchemaCatalog) (Query, bool) {
	if goal, ok := deterministicFQDNInventoryGoal(question, catalog); ok {
		q := QueryFromGoal(goal, question, SourceFQDNHierarchy)
		q.Traversal = TraversalHierarchy
		q.ExcludeRoot = isSubdomainInventoryQuestion(question)
		return q, true
	}
	if intent, ok := deterministicTypedRelationIntent(question, catalog); ok {
		q := QueryFromGoal(intent.Goal, question, SourceTypedRelation)
		q.Traversal = TraversalRoute
		q.Hops = append([]PlanHop(nil), intent.Hops...)
		return q, true
	}
	if goal, ok := deterministicExplicitOrganizationGoal(question, catalog); ok {
		return QueryFromGoal(goal, question, SourceOrganizationRelation), true
	}

	return Query{}, false
}
