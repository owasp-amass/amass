// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Every section names a lens the report can run, and every finding a lens
// among its sections.
func TestReportRules(t *testing.T) {
	rules := loadReportRules()
	sections := map[string]bool{}
	for _, s := range rules.Sections {
		if _, ok := reportSection(s.Lens); !ok || s.Title == "" {
			t.Errorf("section %+v", s)
		}

		sections[s.Lens] = true
	}
	for _, f := range rules.Findings {
		if !sections[f.Lens] || f.Kind == "" || f.Title == "" || f.Priority < 1 {
			t.Errorf("finding %+v", f)
		}
	}
	if l, ok := SubjectLensNamed(LensReport); !ok || l.Find == nil {
		t.Error("the report lens is not registered")
	}
}

func TestFindReport(t *testing.T) {
	defer func(f func() time.Time) { reportNow = f }(reportNow)
	reportNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }
	defer func(f func() time.Time) { certificateNow = f }(certificateNow)
	certificateNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := postureFixture()
	r, err := FindReport(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Sections) != len(loadReportRules().Sections) {
		t.Errorf("sections = %d", len(r.Sections))
	}
	for _, s := range r.Sections {
		if s.Error != "" {
			t.Errorf("%s: %s", s.Lens, s.Error)
		}
	}

	text := r.Text()
	for _, want := range []string{"# Attack surface report: owasp.org", "## Key findings", "## Dangling DNS",
		"## Email security", "```text", "not a live scan"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if len(r.Findings) == 0 {
		t.Fatalf("no key findings:\n%s", text)
	}
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i-1].Priority > r.Findings[i].Priority {
			t.Errorf("findings out of priority order: %+v", r.Findings)
		}
	}
}
