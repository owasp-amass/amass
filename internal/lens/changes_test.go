// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func day(m time.Month, d int) time.Time { return time.Date(2026, m, d, 0, 0, 0, 0, time.UTC) }

// changesFixture dates the vendor fixture: everything stored in January and
// seen again on 10 November, except a name and an address record first
// stored in November and an address and its record last seen in September.
func changesFixture() graphtest.VendorGraph {
	g := graphtest.VendorFixture()
	for id, a := range g.Assets {
		a.CreatedAt, a.LastSeen = day(time.January, 5), day(time.November, 10)
		g.Assets[id] = a
	}
	for i := range g.Links {
		g.Links[i].CreatedAt, g.Links[i].LastSeen = day(time.January, 5), day(time.November, 10)
	}

	portal := g.Assets["portal.colgate.edu"]
	portal.CreatedAt = day(time.November, 5)
	g.Assets["portal.colgate.edu"] = portal
	ip := g.Assets["ip-own"]
	ip.LastSeen = day(time.September, 1)
	g.Assets["ip-own"] = ip
	for i, e := range g.Links {
		switch {
		case e.FromID == "www.colgate.edu" && e.ToID == "ip-cdn":
			g.Links[i].CreatedAt = day(time.November, 6)
		case e.FromID == "nb-own" && e.ToID == "ip-own":
			g.Links[i].LastSeen = day(time.September, 1)
		}
	}

	return g
}

func TestFindChanges(t *testing.T) {
	g := changesFixture()
	r, err := FindChanges(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], day(time.November, 1), LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	find := func(groups []ChangeGroup, key, example string) bool {
		for _, c := range groups {
			if c.Key == key && strings.Contains(strings.Join(c.Examples, "|"), example) {
				return true
			}
		}
		return false
	}
	if !find(r.NewAssets, "FQDN", "portal.colgate.edu") || len(r.NewAssets) != 1 {
		t.Errorf("new assets = %+v", r.NewAssets)
	}
	if !find(r.NewRelations, "dns", "www.colgate.edu --dns_record--> 151.101.1.1") {
		t.Errorf("new relations = %+v", r.NewRelations)
	}
	if !find(r.QuietAssets, "IPAddress", "149.43.1.1") {
		t.Errorf("quiet assets = %+v", r.QuietAssets)
	}
	if !find(r.QuietRelations, "network", "149.43.0.0/16 --contains--> 149.43.1.1") {
		t.Errorf("quiet relations = %+v", r.QuietRelations)
	}

	text := FormatChangesReport(r)
	for _, w := range []string{"since 2026-11-01", "First stored since then", "Not seen again since then",
		"not proven removed"} {
		if !strings.Contains(text, w) {
			t.Errorf("report lacks %q:\n%s", w, text)
		}
	}
}

// When no enumeration has seen the subject since the time, nothing is
// called quiet.
func TestFindChangesWithoutALaterEnumeration(t *testing.T) {
	g := changesFixture()
	r, err := FindChanges(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], day(time.November, 12), LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.QuietAssets)+len(r.QuietRelations) != 0 ||
		!strings.Contains(FormatChangesReport(r), "No enumeration has seen it since") {
		t.Errorf("quiet without a later enumeration: %+v", r)
	}
}

func TestDefaultChangesWindow(t *testing.T) {
	defer func(f func() time.Time) { changesNow = f }(changesNow)
	changesNow = func() time.Time { return day(time.November, 14) }
	if got := DefaultChangesSince(); !got.Equal(day(time.October, 15)) {
		t.Errorf("default window starts %s", got)
	}
}
