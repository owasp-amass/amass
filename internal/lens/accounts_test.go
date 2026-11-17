// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestFindAccounts(t *testing.T) {
	g := graphtest.VendorFixture()
	n := 0
	add := func(raw string) string {
		n++
		id := "u-acct-" + string(rune('a'+n))
		g.Assets[id] = graph.Asset{ID: id, Type: "URL", Key: raw, Content: map[string]any{"url": raw}}
		return id
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	for _, raw := range []string{
		"https://github.com/colgate",
		"https://twitter.com/colgateuniv",
		"https://www.linkedin.com/company/colgate-university",
		"https://github.com/features", // a reserved site page, not an account
		"https://www.colgate.edu/",    // not a known platform
	} {
		link("colgate", "social_media_profile", add(raw))
	}

	r, err := FindAccounts(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]AccountEntry{}
	for _, a := range r.Accounts {
		got[a.Platform] = a
	}
	if len(r.Accounts) != 3 {
		t.Fatalf("accounts = %+v", r.Accounts)
	}
	if gh := got["GitHub"]; gh.Handle != "colgate" || gh.Type != "code" {
		t.Errorf("github = %+v", gh)
	}
	if x := got["X"]; x.Handle != "colgateuniv" {
		t.Errorf("x = %+v", x)
	}
	if li := got["LinkedIn"]; li.Handle != "colgate-university" {
		t.Errorf("linkedin = %+v", li)
	}
	// The reserved GitHub page and the plain website are not accounts.
	for _, a := range r.Accounts {
		if a.Handle == "features" || strings.Contains(a.URL, "colgate.edu") {
			t.Errorf("non-account matched: %+v", a)
		}
	}

	text := r.Text()
	for _, want := range []string{"GitHub: colgate", "LinkedIn: colgate-university"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestMatchAccount(t *testing.T) {
	rules := loadAccountRules()
	cases := []struct {
		raw, platform, handle string
		ok                    bool
	}{
		{"https://github.com/owasp-amass", "GitHub", "owasp-amass", true},
		{"http://www.twitter.com/jeff", "X", "jeff", true},
		{"https://x.com/jeff", "X", "jeff", true},
		{"https://www.linkedin.com/in/jeff-foley", "LinkedIn", "jeff-foley", true},
		{"https://youtube.com/@colgate", "YouTube", "colgate", true},
		{"https://github.com/login", "", "", false},
		{"https://example.com/colgate", "", "", false},
	}
	for _, c := range cases {
		platform, entry, ok := matchAccount(rules, c.raw)
		if ok != c.ok || platform != c.platform || (ok && entry.Handle != c.handle) {
			t.Errorf("matchAccount(%q) = (%q,%q,%v), want (%q,%q,%v)", c.raw, platform, entry.Handle, ok,
				c.platform, c.handle, c.ok)
		}
	}
}
