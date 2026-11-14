// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/graph"
	"github.com/owasp-amass/amass/v5/internal/ai/lens"
)

// deterministicThirdPartyQuery compiles an explicit vendor question about
// a named organization or domain.
func deterministicThirdPartyQuery(question string) (Query, bool) {
	m := lens.VendorQuestion.FindStringSubmatch(question)
	if len(m) != 2 {
		return Query{}, false
	}

	name := strings.TrimSpace(m[1])
	name = strings.TrimSuffix(strings.TrimSuffix(name, "'s"), "’s")
	for _, suffix := range []string{" organization", " organisation", " company"} {
		if len(name) > len(suffix) && strings.EqualFold(name[len(name)-len(suffix):], suffix) {
			name = strings.TrimSpace(name[:len(name)-len(suffix)])
		}
	}
	if name == "" || len(name) > 200 || strings.ContainsAny(name, "?;") {
		return Query{}, false
	}

	subject := PlanSubject{Type: "Organization", Name: name}
	if graph.DomainName.MatchString(name) {
		subject = PlanSubject{Type: "FQDN", Field: "name", Value: strings.ToLower(name)}
	}

	return thirdPartyQuery(question, subject, SourceThirdPartyLens), true
}

func thirdPartyQuery(question string, subject PlanSubject, source string) Query {
	return Query{
		Version:   QueryVersion,
		Question:  question,
		Subject:   subject,
		Traversal: TraversalExplore,
		Direction: "both",
		Purpose:   "connected",
		Lens:      lens.LensThirdParty,
		Source:    source,
	}
}
