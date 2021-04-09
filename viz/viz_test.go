// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package viz

import (
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
			err := g.UpsertA(tc.fqdn, tc.addr, tc.source, tc.eventID)

			if err != nil {
				t.Errorf("Error inserting A record.\n%v", err)
			}
			gotNode, gotEdge := VizData(g, []string{tc.eventID})
			if gotNode == nil {
				t.Errorf("Failed to obtain node.\n%v", gotNode)
			}
			if gotEdge == nil {
				t.Errorf("Failed to obtain edge.\n%v", gotEdge)
			}

		})
	}
}
