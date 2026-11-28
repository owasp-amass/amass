// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/lens"
)

// Two findings of one document that put each of two organizations over the
// other are both rejected; the rest are kept.
func TestDropContradictions(t *testing.T) {
	rel := func(subj, pred, obj string) DocumentStatement {
		return DocumentStatement{Kind: FindingRelation, Subject: subj, SubjectType: "Organization", Predicate: pred,
			Object: obj, ObjectType: "Organization"}
	}
	kept, rejected := dropContradictions([]DocumentStatement{
		rel("OWASP Lab", "unit_of", "OWASP Foundation"),
		rel("owasp foundation", "subsidiary_of", "OWASP Lab"),
		rel("Grants Office", "unit_of", "OWASP Foundation"),
		rel("Counseling Center", "unit_of", lens.DocumentPublisher),
		rel("OWASP Foundation", "funded_by", "OWASP Lab"),
	})
	if len(rejected) != 2 || !strings.Contains(rejected[0], "also puts") {
		t.Errorf("rejected %v, want the two reversed findings", rejected)
	}
	if len(kept) != 3 {
		t.Errorf("kept %+v, want the unit, the publisher's unit and the funder", kept)
	}
}

// A relation between two names of one organization is no finding.
func TestSameOrganization(t *testing.T) {
	if !sameOrganization(DocumentStatement{Subject: "Utica University", SubjectType: "Organization",
		Object: "UTICA UNIVERSITY", ObjectType: "Organization"}) {
		t.Error("two spellings of one name are two organizations")
	}
	if sameOrganization(DocumentStatement{Subject: "Utica University", SubjectType: "Organization",
		Object: "Utica Products", ObjectType: "Organization"}) {
		t.Error("two organizations are one")
	}
}
