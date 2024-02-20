// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/engine/graph"
)

func TestViz(t *testing.T) {
	g := graph.NewGraph("memory", "", "")

	tt := []struct {
		fqdn string
		addr string
	}{
		{fqdn: "dev.example.domain", addr: "127.0.0.1"},
	}

	for _, tc := range tt {
		t.Run("Testing VizData...", func(t *testing.T) {
			_, err := g.UpsertA(context.Background(), tc.fqdn, tc.addr)

			if err != nil {
				t.Errorf("Error inserting A record.\n%v", err)
			}
			gotNode, gotEdge := VizData([]string{"example.domain"}, time.Time{}, g)
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
			Label: "a_record",
			Title: "a_record",
		},
	}
}

func testNodes() []Node {
	return []Node{
		{
			ID:    0,
			Type:  "FQDN",
			Label: "owasp.org",
			Title: "FQDN: owasp.org",
		},
		{
			ID:    1,
			Type:  "IPAddress",
			Label: "205.251.199.98",
			Title: "IPAddress: 205.251.199.98",
		},
	}
}
