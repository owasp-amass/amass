// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// The publisher placeholder is only ever the parent of a unit_of finding,
// whose unit must be written where it is quoted; it is never a lead.
func TestPublisherUnitFindings(t *testing.T) {
	v := documentVocabulary()
	chunk := "The Counseling Center is open weekdays. The college does not operate the Bookstore Annex."
	unit := func(subject, predicate, quote string) DocumentStatement {
		return DocumentStatement{Kind: FindingRelation, Subject: subject, SubjectType: "Organization",
			Predicate: predicate, Object: lens.DocumentPublisher, ObjectType: "Organization", Quote: quote}
	}
	for _, tc := range []struct {
		s  DocumentStatement
		ok bool
	}{
		{unit("Counseling Center", "unit_of", "The Counseling Center is open weekdays."), true},
		{unit("Counseling Center", "member_of", "The Counseling Center is open weekdays."), false},
		{unit("Health Center", "unit_of", "The Counseling Center is open weekdays."), false},
		{unit("Bookstore Annex", "unit_of", "The college does not operate the Bookstore Annex."), false},
		{DocumentStatement{Kind: FindingRelation, Subject: lens.DocumentPublisher, SubjectType: "Organization",
			Predicate: "unit_of", Object: "Counseling Center", ObjectType: "Organization",
			Quote: "The Counseling Center is open weekdays."}, false},
	} {
		reason := v.validateRelation(tc.s, chunk)
		if (reason == "") != tc.ok {
			t.Errorf("%s %s %s: reason %q, want ok %v", tc.s.Subject, tc.s.Predicate, tc.s.Object, reason, tc.ok)
		}
	}
	if v.validateAsset(DocumentStatement{Kind: FindingAsset, Subject: lens.DocumentPublisher,
		SubjectType: "Organization", Quote: "The Counseling Center is open weekdays."}, chunk) == "" {
		t.Error("the placeholder was accepted as an asset")
	}

	for _, l := range statementLeads(review.StoredStatement{Kind: FindingRelation, Subject: "Counseling Center",
		SubjectType: "Organization", Predicate: "unit_of", Object: lens.DocumentPublisher,
		ObjectType: "Organization"}, "US") {
		if l.name == lens.DocumentPublisher {
			t.Error("the placeholder became a lead")
		}
	}

	if !strings.Contains(documentPrompt(documentVocabulary()), lens.DocumentPublisher) {
		t.Error("the prompt does not tell the model about the publisher placeholder")
	}
}
