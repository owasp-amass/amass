// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"regexp"
	"strings"
)

// This fast path intentionally recognizes only a narrow, explicitly
// structured question. It is not a general natural-language parser; any
// ambiguity falls through to the normal model planner.
var explicitOrgQuestion = regexp.MustCompile(`(?i)^\s*(?:which|what)\s+organizations?\b`)
var hostnameInQuestion = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_.-])([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?){1,})(?:[^a-z0-9_.-]|$)`)
var topParentTerms = regexp.MustCompile(`(?i)\b(?:highest|ultimate|topmost|top-level)\s+(?:documented\s+)?parent\b`)

// deterministicExplicitOrganizationGoal resolves only explicitly provided
// FQDN + Organization + relationship labels and a single unique taxonomy
// route. All full-catalog validation still applies. It neither looks up the
// graph nor asserts that any edge exists.
func deterministicExplicitOrganizationGoal(question string, catalog SchemaCatalog) (InvestigationGoal, bool) {
	var zero InvestigationGoal
	if !explicitOrgQuestion.MatchString(question) || topParentTerms.MatchString(question) {
		return zero, false
	}
	if !strings.Contains(strings.ToLower(question),
		"connect") && !strings.Contains(strings.ToLower(question), "associat") {
		return zero, false
	}

	relations := catalog.Relations()
	hint, ok := explicitRelationLabels(question, relations)
	if !ok {
		return zero, false
	}

	hosts := hostnameInQuestion.FindAllStringSubmatch(question, -1)
	if len(hosts) != 1 {
		return zero, false
	}

	hostname := hosts[0][1]
	// Avoid making FQDN assumptions in URLs, emails, or other identifiers.
	if strings.Contains(question, "://") || strings.Contains(question, "@") {
		return zero, false
	}

	selectors, ok := catalog.(AssetSearchCatalog)
	if !ok {
		return zero, false
	}

	fields := selectors.SearchFields()
	foundSelector := false
	for _, schema := range fields {
		if schema.Type != "FQDN" {
			continue
		}
		for _, field := range schema.Fields {
			if field == "name" {
				foundSelector = true
				break
			}
		}
		if foundSelector {
			break
		}
	}
	if !foundSelector {
		return zero, false
	}

	goal := InvestigationGoal{
		Subject:     PlanSubject{Type: "FQDN", Field: "name", Value: hostname},
		TargetTypes: []string{"Organization"}, Direction: "both", Purpose: "connected",
	}
	grounded, ok := applyExplicitRelationGrounding(goal, hint, relations)
	if !ok {
		return zero, false
	}
	if err := validateGoal(grounded, relations, fields); err != nil {
		return zero, false
	}

	return grounded, true
}
