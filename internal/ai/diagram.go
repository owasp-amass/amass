// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"strings"
	"unicode"
)

// Mermaid converts an already-bounded graph walk to a safe static diagram.
// Generated node IDs are local to this diagram; original OAM IDs remain in the labels.
func Mermaid(w WalkResult) string {
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	ids := map[string]string{}
	for n, a := range w.Nodes {
		synthetic := fmt.Sprintf("n%d", n)
		ids[a.ID] = synthetic
		fmt.Fprintf(&b, "  %s[\"%s\"]\n", synthetic, safeDiagramText(a.Type+": "+a.Key))
	}
	for _, edge := range w.Edges {
		from, ok1 := ids[edge.FromID]
		to, ok2 := ids[edge.ToID]
		if !ok1 || !ok2 {
			continue
		}
		fmt.Fprintf(&b, "  %s -->|%s| %s\n", from, safeDiagramText(edge.Label), to)
	}
	if w.Truncated {
		b.WriteString("  %% Partial graph: traversal was truncated\n")
	}
	return b.String()
}
func safeDiagramText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() > 96 {
			break
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_ .:/@", r) {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
