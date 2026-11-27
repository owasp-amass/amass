// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

func TestRelationDetailShowsPorts(t *testing.T) {
	e := graph.Relation{Label: "port", Content: map[string]any{"port_number": 443, "protocol": "tcp"}}
	if got := lens.RelationDetail(e); got != "443/tcp" {
		t.Errorf("detail = %q, want 443/tcp", got)
	}
	if got := lens.RelationDetail(graph.Relation{Label: "node"}); got != "" {
		t.Errorf("detail = %q for a relation without fields", got)
	}

	w := lens.WitnessOf(e, graph.Asset{ID: "a", Type: "FQDN", Key: "www.example.com"}, graph.Asset{ID: "b", Type: "Service", Key: "x"})
	if line := (EvidenceItem{ID: "E1", WitnessEdge: w}).Line(); !strings.Contains(line, "--port 443/tcp-->") {
		t.Errorf("evidence line lacks the port: %s", line)
	}
}
