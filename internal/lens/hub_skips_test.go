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

// hubGraph is a graph whose database derives a hub limit of 140 for phones.
type hubGraph struct{ graphtest.FakeGraph }

func (hubGraph) HubRule(_ context.Context, src graph.HubSource, fallback int) graph.HubRule {
	if src.Label == "phone" {
		return graph.HubRule{Limit: 140, Derived: true}
	}
	return graph.HubRule{Limit: fallback}
}

// A value over the hub limit is recorded once, with the limit that stopped
// it and where the limit came from, and listed most shared first.
func TestHubSkips(t *testing.T) {
	ctx := context.Background()
	g := hubGraph{graphtest.SampleGraph()}
	skips := &hubSkips{}

	phone := derivedHub(ctx, g, "phone", "in", GapMaxShared, skips)
	if phone.over("+1 555 0100", 140, false) {
		t.Error("a value at the derived limit was stopped")
	}
	if !phone.over("+1 555 0199", 812, false) {
		t.Error("a value over the derived limit was not stopped")
	}
	// asked again, it is stopped again and still recorded once
	if !phone.over("+1 555 0199", 812, false) {
		t.Error("a value over the derived limit was stopped only once")
	}
	address := derivedHub(ctx, g, "street_address", "in", 10, skips)
	if !address.over("1 Main St", 11, false) {
		t.Error("a value over the fallback was not stopped")
	}
	token := fixedHub("TXT verification token", GapMaxShared, skips)
	if !token.over("google-site-verification=x", 51, true) {
		t.Error("a search with more matches was not stopped")
	}

	got := skips.sorted()
	if len(got) != 3 || got[0].Value != "+1 555 0199" || !got[0].Derived || got[0].Limit != 140 ||
		got[1].Derived || got[1].Limit != GapMaxShared {
		t.Fatalf("skips = %+v", got)
	}
	text := hubSkipText(got)
	for _, want := range []string{"3 shared value(s) did not count", "shared by 812 assets (hub limit 140 for phone, " +
		"from the database)", "more than 50 assets (hub limit 50 for TXT verification token, fixed)"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q lacks %q", text, want)
		}
	}
	if hubSkipText(nil) != "" {
		t.Error("no skips gave text")
	}
}
