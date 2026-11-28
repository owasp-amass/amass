// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// sameOrganization reports whether a relation finding's two ends name one
// organization once their names are normalized ("Utica University" and
// "utica university inc.").
func sameOrganization(s DocumentStatement) bool {
	return s.SubjectType == "Organization" && s.ObjectType == "Organization" &&
		semantics.OrgNameKey(s.Subject) == semantics.OrgNameKey(s.Object)
}

// dropContradictions removes the hierarchy findings of one document that
// cannot both be true: two that put each of two organizations over the
// other. It returns the findings kept and why the others were rejected.
func dropContradictions(statements []DocumentStatement) ([]DocumentStatement, []string) {
	ends := func(s DocumentStatement) (child, parent string, ok bool) {
		if s.Kind != FindingRelation || !lens.HierarchyPredicate(s.Predicate) ||
			s.Subject == lens.DocumentPublisher || s.Object == lens.DocumentPublisher {
			return "", "", false
		}
		return semantics.OrgNameKey(s.Subject), semantics.OrgNameKey(s.Object), true
	}

	over := map[[2]string]bool{}
	for _, s := range statements {
		if child, parent, ok := ends(s); ok {
			over[[2]string{parent, child}] = true
		}
	}

	kept := make([]DocumentStatement, 0, len(statements))
	var rejected []string
	for _, s := range statements {
		if child, parent, ok := ends(s); ok && over[[2]string{child, parent}] {
			rejected = append(rejected, fmt.Sprintf("%s: the document also puts %q over %q", s.Predicate, s.Subject,
				s.Object))
			continue
		}
		kept = append(kept, s)
	}
	return kept, rejected
}
