// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// Mermaid converts an already-bounded graph walk to a safe static diagram.
// Generated node IDs are local to this diagram; original OAM IDs remain in the labels.
func Mermaid(w graph.WalkResult) string {
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

// GapDiagram draws an ownership-gap report as a static flowchart: the subject
// organization, each candidate it could own, and the proposed attribution
// edge, styled by the decision (a thick edge proposes, a dotted edge waits for
// review, a plain edge is weak). It is empty when there are no candidates.
func GapDiagram(r lens.OwnershipGapReport) string {
	if len(r.Candidates) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("flowchart LR\n")
	fmt.Fprintf(&b, "  owner[\"%s\"]\n", safeDiagramText(r.Owner.Type+": "+graph.AssetLabel(r.Owner)))

	for i, c := range r.Candidates {
		node := fmt.Sprintf("c%d", i)
		fmt.Fprintf(&b, "  %s[\"%s\"]\n", node, safeDiagramText(c.Type+": "+c.Asset))

		arrow := "-->"
		switch c.Decision {
		case lens.GapPropose:
			arrow = "==>"
		case lens.GapReview:
			arrow = "-.->"
		}

		rel, ownerFrom := "attribution", false
		if c.Attachment != nil {
			rel = c.Attachment.Label
			ownerFrom = c.Attachment.FromID == r.Owner.ID
		}

		edge := safeDiagramText(c.Decision + ": " + rel)
		if ownerFrom {
			fmt.Fprintf(&b, "  owner %s|%s| %s\n", arrow, edge, node)
		} else {
			fmt.Fprintf(&b, "  %s %s|%s| owner\n", node, arrow, edge)
		}
		fmt.Fprintf(&b, "  class %s %s\n", node, gapDecisionClass(c.Decision))
	}

	b.WriteString("  class owner subject\n")
	b.WriteString("  classDef subject fill:#1f2937,color:#fff,stroke:#111827\n")
	b.WriteString("  classDef propose fill:#dcfce7,stroke:#16a34a\n")
	b.WriteString("  classDef review fill:#fef9c3,stroke:#ca8a04\n")
	b.WriteString("  classDef weak fill:#f3f4f6,stroke:#9ca3af\n")
	if r.Truncated {
		b.WriteString("  %% Partial: the gap search was truncated\n")
	}

	return b.String()
}

func gapDecisionClass(d string) string {
	switch d {
	case lens.GapPropose:
		return "propose"
	case lens.GapReview:
		return "review"
	default:
		return "weak"
	}
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
