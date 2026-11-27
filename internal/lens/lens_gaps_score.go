// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// ScoreGap rates a candidate's signals by their catalog strength and
// weight. A strong signal (shared registrant details, a shared verification
// token) points to one owner; a supporting one (hosting, co-listing) is
// consistent with many; a tiebreaker (a name token, a TLS fingerprint)
// only ranks and never corroborates a proposal; a negative one (a parked
// page) counts against
// ownership and keeps the candidate from being proposed. Each signal counts
// at most twice toward the score, which ranks candidates and is not a
// probability. A strong signal that rests on contributions (Contributed)
// counts as supporting.
func ScoreGap(signals []GapSignal, attachable bool) (float64, string) {
	return scoreSignals(signals, attachable, LookupOwnershipSignal)
}

// scoreSignals applies the shared decision rules to signals defined by
// lookup.
func scoreSignals(signals []GapSignal, attachable bool, lookup func(string) (OwnershipSignal, bool)) (float64, string) {
	count := map[string]int{}
	corroborating := map[string]bool{}
	strong := 0
	negative := false
	score := 0.0
	for _, s := range signals {
		def, ok := lookup(s.Signal)
		if !ok {
			continue
		}
		if def.Strength == StrengthNegative {
			negative = true
			score -= def.Weight
			continue
		}

		count[s.Signal]++
		if !def.Tiebreaker {
			corroborating[s.Signal] = true
		}
		if def.Strength == StrengthStrong && !s.Contributed {
			strong++
		}
		if count[s.Signal] <= 2 {
			w := def.Weight
			if s.Weight > 0 && s.Weight < w {
				w = s.Weight
			}
			score += w
		}
	}

	// A strong signal is corroborated by a different signal that is not a
	// tiebreaker.
	score = math.Max(0, math.Min(1, score))
	switch {
	case attachable && !negative && (strong >= 2 || (strong >= 1 && len(corroborating) >= 2)):
		return score, GapPropose
	case strong >= 1 || len(count) >= 2:
		return score, GapReview
	default:
		return score, GapWeak
	}
}

// attachment finds, along the candidate's ownership chain, the closest
// asset that an OAM relationship can attribute to an Organization (a
// contact record's organization, an organization's website) and that has
// no such relationship yet, and the assets that edge would bring under the
// subject.
func (g *gapSearch) attachment(a graph.Asset, ctl controller) ([]ProposedEdge, []graph.Asset, error) {
	for _, v := range ctl.visited {
		edges := g.attachEdges(v)
		if len(edges) == 0 {
			continue
		}

		gains, err := g.gains(v)
		return edges, gains, err
	}

	return nil, nil, nil
}

// attachEdges returns the catalog relationships that would attribute v to
// the subject, sorted by label.
func (g *gapSearch) attachEdges(v graph.Asset) []ProposedEdge {
	var out []ProposedEdge
	for _, r := range g.w.relations {
		m, ok := g.w.meaning(r.SourceType, r.Label, r.RelationType, r.DestinationType)
		if !ok {
			continue
		}
		switch {
		case r.SourceType == v.Type && r.DestinationType == "Organization" &&
			(m.Attribution == graph.AttrSameSubject || m.Attribution == graph.AttrController):
			out = append(out, ProposedEdge{FromID: v.ID, FromType: v.Type, From: graph.AssetLabel(v), Label: r.Label,
				RelationType: r.RelationType, ToID: g.owner.ID, ToType: "Organization", To: graph.AssetLabel(g.owner)})
		case r.SourceType == "Organization" && r.DestinationType == v.Type && m.Attribution == graph.AttrControls &&
			v.Type != "Organization":
			out = append(out, ProposedEdge{FromID: g.owner.ID, FromType: "Organization", From: graph.AssetLabel(g.owner),
				Label: r.Label, RelationType: r.RelationType, ToID: v.ID, ToType: v.Type, To: graph.AssetLabel(v)})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// gains lists the assets that attributing v would bring under the subject.
func (g *gapSearch) gains(v graph.Asset) ([]graph.Asset, error) {
	seen := map[string]bool{v.ID: true}
	queue := []graph.Asset{v}
	var out []graph.Asset
	for len(queue) > 0 && !g.w.outOfReads() {
		cur := queue[0]
		queue = queue[1:]
		steps, err := g.w.steps(cur)
		if err != nil {
			return nil, err
		}
		for _, s := range steps {
			if seen[s.other.ID] || !footprintPass(s) || platformStep(cur, s) || s.other.Type == "Organization" ||
				s.other.Type == "Person" {
				continue
			}

			seen[s.other.ID] = true
			out = append(out, s.other)
			queue = append(queue, s.other)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Type+" "+graph.AssetLabel(out[i]) < out[j].Type+" "+graph.AssetLabel(out[j])
	})
	return out, nil
}

// GapAnswer renders an OwnershipGapReport as plain text.
func GapAnswer(r OwnershipGapReport) string {
	subject := graph.AssetLabel(r.Root) + " (" + r.Root.Type + ")"
	if r.Owner.ID == "" {
		return "No documented owner for " + subject + ", so there is no footprint to compare unattributed assets with."
	}

	var b strings.Builder
	if len(r.Candidates) == 0 {
		fmt.Fprintf(&b, "No unattributed assets share ownership signals with the %d assets controlled by %s.",
			r.Footprint, graph.AssetLabel(r.Owner))
		if r.Truncated && r.Reason != "" {
			fmt.Fprintf(&b, " Results are partial (%s).", r.Reason)
		}
		b.WriteString(hubSkipText(r.HubSkips))
		b.WriteString(undeterminedText(r.Undetermined))

		return b.String()
	}

	fmt.Fprintf(&b, "%d unattributed asset(s) share signals with the %d assets controlled by %s:\n", len(r.Candidates),
		r.Footprint, graph.AssetLabel(r.Owner))
	for _, c := range r.Candidates {
		kinds := map[string]bool{}
		var names []string
		for _, s := range c.Signals {
			if !kinds[s.Kind] {
				kinds[s.Kind] = true
				names = append(names, s.Kind)
			}
		}

		fmt.Fprintf(&b, "  [%s %.2f] %s %s: %s", c.Decision, c.Score, c.Type, c.Asset, strings.Join(names, ", "))
		if c.Attachment != nil {
			fmt.Fprintf(&b, "; would record %s", c.Attachment)
			for _, alt := range c.Alternatives {
				fmt.Fprintf(&b, " or %s", alt.Label)
			}
		} else {
			b.WriteString("; no OAM relationship can record its owner without new records")
		}
		if len(c.Gains) > 0 {
			fmt.Fprintf(&b, "; brings %s", strings.Join(c.Gains, ", "))
		}

		b.WriteString("\n")
	}

	b.WriteString("These are proposals from stored signals, not documented ownership. Nothing has been written.")
	b.WriteString(hubSkipText(r.HubSkips))
	b.WriteString(undeterminedText(r.Undetermined))
	if r.Truncated {
		b.WriteString(" Results are partial (" + r.Reason + ").")
	}

	return b.String()
}

// undeterminedText names the assets left out because their owner search was
// inconclusive, up to lensMaxExamples of them.
func undeterminedText(u []UndeterminedOwner) string {
	if len(u) == 0 {
		return ""
	}

	var names []string
	for i, o := range u {
		if i == lensMaxExamples {
			names = append(names, fmt.Sprintf("and %d more", len(u)-i))
			break
		}
		names = append(names, o.Type+" "+o.Asset)
	}
	return fmt.Sprintf(" %d asset(s) with signals were left out because the search for their owner stopped at its limit "+
		"before reaching one (%s); a higher owner step limit (-owner-steps, MCP owner_steps) settles them.",
		len(u), strings.Join(names, ", "))
}
