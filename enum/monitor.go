// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"strings"

	"github.com/caffix/netmap"
)

const falsePositiveThreshold int = 100

func (e *Enumeration) checkForMissedWildcards(ip string) {
	addr := netmap.Node(ip)

	if count, err := e.graph.CountInEdges(e.ctx, addr, "a_record", "aaaa_record"); err != nil || count < falsePositiveThreshold {
		return
	}

	edges, err := e.graph.ReadInEdges(e.ctx, addr, "a_record", "aaaa_record")
	if err != nil {
		return
	}

	subsToNodes := make(map[string][]netmap.Node)
	for _, edge := range edges {
		name := e.graph.NodeToID(edge.From)
		if name == "" {
			continue
		}

		parts := strings.Split(name, ".")
		sub := strings.Join(parts[1:], ".")
		subsToNodes[sub] = append(subsToNodes[sub], edge.From)
	}

	for sub, nodes := range subsToNodes {
		if len(nodes) < falsePositiveThreshold {
			continue
		}

		e.Config.BlacklistSubdomain(sub)
		for _, node := range nodes {
			_ = e.graph.DeleteNode(e.ctx, node)
		}
	}
}
