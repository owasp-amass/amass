// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// WitnessPathID is derived only from real asset and edge identifiers. It is
// stable for a given directed traversal path and does not assert ownership.
func WitnessPathID(match PlanMatch) string {
	var s strings.Builder
	for i, n := range match.Nodes {
		s.WriteString(n.ID)
		s.WriteByte(0)
		if i < len(match.Edges) {
			e := match.Edges[i]
			s.WriteString(e.ID)
			s.WriteByte(0)
		}
	}

	sum := sha256.Sum256([]byte(s.String()))
	return hex.EncodeToString(sum[:12])
}

type PlanMatch struct {
	Nodes  []Asset    `json:"nodes"`
	Edges  []Relation `json:"edges"`
	PathID string     `json:"path_id,omitempty"`
}
