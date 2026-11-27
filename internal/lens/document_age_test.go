// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestDocumentDated(t *testing.T) {
	ev := []graph.Evidence{
		graphtest.SimpleProp(propDocCreated, "2010-03-01T09:00:00Z"),
		graphtest.SimpleProp(propDocModified, "2011-06-15T10:30:00-04:00"),
	}
	if got := documentDated(ev); got.Year() != 2011 || got.Month() != time.June {
		t.Errorf("documentDated = %v, want the newer June 2011 date", got)
	}
	// tool defaults and unparsable dates are no dates
	ev = []graph.Evidence{graphtest.SimpleProp(propDocCreated, "1601-01-01T00:00:00Z"),
		graphtest.SimpleProp(propDocModified, "sometime in 2011")}
	if got := documentDated(ev); !got.IsZero() {
		t.Errorf("documentDated = %v, want none", got)
	}
	if got := documentDated([]graph.Evidence{graphtest.SimpleProp(propDocCreated, "2024-02-29")}); got.Year() != 2024 {
		t.Errorf("a bare date was not read: %v", got)
	}
	// a PDF date stored without its "D:" prefix, as some producers write it
	ev = []graph.Evidence{graphtest.SimpleProp(propDocCreated, "20091105124021")}
	if got := documentDated(ev); got.Year() != 2009 || got.Month() != time.November {
		t.Errorf("documentDated = %v, want November 2009", got)
	}
}

func TestStaleDocument(t *testing.T) {
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		dated time.Time
		want  bool
	}{
		{time.Date(2010, 7, 1, 0, 0, 0, 0, time.UTC), true},
		{time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), false},
		{time.Time{}, false},
	} {
		if got := StaleDocument(tc.dated, now); got != tc.want {
			t.Errorf("StaleDocument(%v) = %v, want %v", tc.dated, got, tc.want)
		}
	}

	// a stale document still states history
	if staleFinding(true, "formerly_known_as") || !staleFinding(true, "unit_of") || staleFinding(false, "unit_of") {
		t.Error("staleFinding keeps or drops the wrong findings")
	}
}
