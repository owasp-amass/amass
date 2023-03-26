// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"context"
	"testing"

	"github.com/caffix/netmap"
)

func TestViz(t *testing.T) {
	g := netmap.NewGraph(netmap.NewCayleyGraphMemory())
	defer g.Close()

	tt := []struct {
		fqdn    string
		addr    string
		source  string
		tag     string
		eventID string
	}{
		{fqdn: "dev.example.domain", addr: "127.0.0.1", source: "test", tag: "foo", eventID: "barbazz"},
	}

	for _, tc := range tt {
		t.Run("Testing VizData...", func(t *testing.T) {
			err := g.UpsertA(context.Background(), tc.fqdn, tc.addr, tc.source, tc.eventID)

			if err != nil {
				t.Errorf("Error inserting A record.\n%v", err)
			}
			gotNode, gotEdge := VizData(context.Background(), g, []string{tc.eventID})
			if gotNode == nil {
				t.Errorf("Failed to obtain node.\n%v", gotNode)
			}
			if gotEdge == nil {
				t.Errorf("Failed to obtain edge.\n%v", gotEdge)
			}

		})
	}
}

func testEdges() []Edge {
	return []Edge{
		{
			From:  0,
			To:    1,
			Label: "",
			Title: "a_record",
		},
	}
}

func testNodes() []Node {
	return []Node{
		{
			ID:         0,
			Type:       "domain",
			Label:      "owasp.org",
			Title:      "domain: owasp.org",
			Source:     "DNS",
			ActualType: "fqdn",
		},
		{
			ID:         1,
			Type:       "address",
			Label:      "205.251.199.98",
			Title:      "address: 205.251.199.98",
			Source:     "DNS",
			ActualType: "ipaddr",
		},
	}
}
