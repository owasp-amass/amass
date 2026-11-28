// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// listedGraph answers value searches for the reputation_listing property.
type listedGraph struct {
	graphtest.FakeGraph
	listed map[string][]graph.Asset // feed name -> listed assets
}

func (g listedGraph) FindByTagValue(_ context.Context, assetType, name, value string, _ bool,
	_ int) ([]graph.Asset, bool, error) {
	if name != semantics.ReputationListingProperty {
		return nil, false, nil
	}
	var out []graph.Asset
	for _, a := range g.listed[value] {
		if a.Type == assetType {
			out = append(out, a)
		}
	}
	return out, false, nil
}

func (listedGraph) FindByAttribute(context.Context, string, string, string, bool, int) ([]graph.Asset, bool,
	error) {
	return nil, false, nil
}

// Only the footprint's listed addresses and netblocks are noted, with the
// feed's title.
func TestReputationListed(t *testing.T) {
	asset := func(id, typ, key, field string) graph.Asset {
		return graph.Asset{ID: id, Type: typ, Key: key, Content: map[string]any{field: key}}
	}
	ip := asset("ip1", "IPAddress", "198.51.100.7", "address")
	nb := asset("nb1", "Netblock", "203.0.113.0/24", "cidr")
	other := asset("ip2", "IPAddress", "198.51.100.9", "address")
	g := listedGraph{listed: map[string][]graph.Asset{"tor-exit": {ip, other}, "spamhaus-drop": {nb}}}

	var got []string
	if err := reputationListed(context.Background(), g, map[string]graph.Asset{"ip1": ip, "nb1": nb},
		func(example string) { got = append(got, example) }); err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	want := []string{"198.51.100.7 (Tor exit relay)", "203.0.113.0/24 (Spamhaus DROP)"}
	if !slices.Equal(got, want) {
		t.Errorf("listed = %q, want %q", got, want)
	}
}
