// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// EvidenceItem is one stored relationship an answer rests on, numbered so
// that prose can cite it as [E1].
type EvidenceItem struct {
	ID string `json:"id"`
	WitnessEdge
	// Sources are the attributed source tags on the edge, when the
	// investigation inspected its provenance.
	Sources []string `json:"sources,omitempty"`
}

// EvidenceBundle is the numbered evidence behind an investigation's answer.
type EvidenceBundle struct {
	Items []EvidenceItem `json:"items"`
	// Subjects are the question's subject and its documented owners. Every
	// item is about them, so prose may name them in any cited sentence.
	Subjects  []string `json:"subjects,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// BuildEvidenceBundle numbers the stored edges behind inv's answer, in
// answer order and without repeats: witnessed paths, vendor witnesses and
// table row witnesses. At most max items are kept.
func BuildEvidenceBundle(inv Investigation, max int) EvidenceBundle {
	var edges []WitnessEdge
	var subjects []string
	for _, m := range inv.Matches {
		edges = append(edges, pathWitness(m)...)
		if len(m.Nodes) > 0 {
			subjects = append(subjects, assetLabel(m.Nodes[0]))
		}
	}
	if r := inv.ThirdPartyReport; r != nil {
		subjects = append(append(subjects, assetLabel(r.Root)), r.Owners...)
		for _, v := range r.Vendors {
			edges = append(edges, v.Witness...)
		}
	}
	if r := inv.ControlledReport; r != nil {
		subjects = append(append(subjects, assetLabel(r.Root)), r.Owners...)
	}
	if r := inv.GapReport; r != nil {
		subjects = append(subjects, assetLabel(r.Root), assetLabel(r.Owner))
		for _, c := range r.Candidates {
			for _, s := range c.Signals {
				edges = append(edges, s.Witness...)
			}
		}
	}
	if r := inv.TableReport; r != nil {
		subjects = append(append(subjects, assetLabel(r.Root)), r.Owners...)
		for _, w := range r.Witness {
			edges = append(edges, w...)
		}
	}

	sources := map[string][]string{}
	if d := inv.EvidenceDossier; d != nil {
		for _, p := range d.Paths {
			for _, e := range p.Edges {
				sources[e.EdgeID] = e.AttributedSources
			}
		}
	}

	var b EvidenceBundle
	seenSubject := map[string]bool{}
	for _, s := range subjects {
		if s != "" && !seenSubject[strings.ToLower(s)] {
			seenSubject[strings.ToLower(s)] = true
			b.Subjects = append(b.Subjects, s)
		}
	}

	seen := map[string]bool{}
	for _, e := range edges {
		key := e.EdgeID
		if key == "" {
			key = e.FromID + "\x00" + e.Label + "\x00" + e.ToID
		}
		if seen[key] {
			continue
		}
		if len(b.Items) >= max {
			b.Truncated = true
			break
		}

		seen[key] = true
		b.Items = append(b.Items, EvidenceItem{ID: fmt.Sprintf("E%d", len(b.Items)+1), WitnessEdge: e,
			Sources: sources[e.EdgeID]})
	}

	return b
}

// Line renders an item as "E1: FQDN www.example.com --dns_record--> IPAddress
// 192.0.2.1 (sources: dns)".
func (i EvidenceItem) Line() string {
	label := i.Label
	if i.Detail != "" {
		label += " " + i.Detail
	}

	line := fmt.Sprintf("%s: %s %s --%s--> %s %s", i.ID, i.FromType, i.From, label, i.ToType, i.To)
	if len(i.Sources) > 0 {
		line += " (sources: " + strings.Join(i.Sources, ", ") + ")"
	}

	return line
}

// String renders the bundle one item per line.
func (b EvidenceBundle) String() string {
	lines := make([]string, 0, len(b.Items))
	for _, i := range b.Items {
		lines = append(lines, i.Line())
	}

	return strings.Join(lines, "\n")
}

var (
	citationGroup = regexp.MustCompile(`\[(E\d+(?:\s*,\s*E\d+)*)\]`)
	citationID    = regexp.MustCompile(`E\d+`)
	sentenceEnd   = regexp.MustCompile(`([.!?])\s+`)
	// identifiers finds hostnames and IPv4 addresses in prose.
	identifiers = regexp.MustCompile(`(?i)\b(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b`)
)

// sentences splits prose into sentences, keeping citations that follow the
// final punctuation with their sentence ("... vendor. [E2] Next").
func sentences(text string) []string {
	text = strings.TrimSpace(strings.Join(strings.Fields(text), " "))
	text = regexp.MustCompile(`([.!?])\s*(\[E\d+(?:\s*,\s*E\d+)*\])`).ReplaceAllString(text, " $2$1")

	var out []string
	for _, s := range sentenceEnd.Split(text, -1) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}

	return out
}

// VerifyCitations checks prose against bundle and returns every problem:
// a sentence without a citation, a citation of an unknown item, an asset of
// the bundle named in a sentence whose citations do not include it, or a
// hostname or IP address that appears nowhere in the evidence. The
// question's subjects may be named in any cited sentence.
// Names are matched longest first, so "www.example.com" does not also count
// as "example.com".
func VerifyCitations(text string, bundle EvidenceBundle) []string {
	byID := map[string]EvidenceItem{}
	var labels []string
	seenLabel := map[string]bool{}
	subject := map[string]bool{}
	for _, l := range bundle.Subjects {
		subject[strings.ToLower(l)] = true
		if len(l) >= 4 && !seenLabel[strings.ToLower(l)] {
			seenLabel[strings.ToLower(l)] = true
			labels = append(labels, l)
		}
	}
	for _, i := range bundle.Items {
		byID[i.ID] = i
		for _, l := range []string{i.From, i.To} {
			if len(l) >= 4 && !seenLabel[strings.ToLower(l)] {
				seenLabel[strings.ToLower(l)] = true
				labels = append(labels, l)
			}
		}
	}

	sort.Slice(labels, func(i, j int) bool { return len(labels[i]) > len(labels[j]) })

	var problems []string
	ss := sentences(text)
	if len(ss) == 0 {
		return []string{"the answer is empty"}
	}
	for n, s := range ss {
		cited := map[string]bool{}
		for _, g := range citationGroup.FindAllStringSubmatch(s, -1) {
			for _, id := range citationID.FindAllString(g[1], -1) {
				if _, ok := byID[id]; !ok {
					problems = append(problems,
						fmt.Sprintf("sentence %d cites %s, which is not in the evidence", n+1, id))
					continue
				}

				cited[id] = true
			}
		}
		if len(cited) == 0 {
			problems = append(problems, fmt.Sprintf("sentence %d has no citation: %q", n+1, s))
			continue
		}

		plain := strings.ToLower(citationGroup.ReplaceAllString(s, ""))
		for _, id := range identifiers.FindAllString(plain, -1) {
			if !inEvidence(id, labels) {
				problems = append(problems, fmt.Sprintf("sentence %d names %s, which is not in the evidence", n+1, id))
			}
		}

		for _, l := range labels {
			ll := strings.ToLower(l)
			if !strings.Contains(plain, ll) {
				continue
			}

			plain = strings.ReplaceAll(plain, ll, strings.Repeat("#", len(ll)))
			if subject[ll] {
				continue
			}

			supported := false
			for id := range cited {
				i := byID[id]
				if strings.EqualFold(i.From, l) || strings.EqualFold(i.To, l) {
					supported = true
					break
				}
			}
			if !supported {
				problems = append(problems, fmt.Sprintf("sentence %d names %s but none of its citations mention it",
					n+1, l))
			}
		}
	}

	return problems
}

// CitedItems returns the bundle items text cites, in bundle order.
func CitedItems(text string, bundle EvidenceBundle) []EvidenceItem {
	cited := map[string]bool{}
	for _, g := range citationGroup.FindAllStringSubmatch(text, -1) {
		for _, id := range citationID.FindAllString(g[1], -1) {
			cited[id] = true
		}
	}

	var out []EvidenceItem
	for _, i := range bundle.Items {
		if cited[i.ID] {
			out = append(out, i)
		}
	}

	return out
}

// inEvidence reports whether an identifier from prose is, or is part of, an
// evidence label (a hostname may appear inside a URL label).
func inEvidence(id string, labels []string) bool {
	for _, l := range labels {
		if strings.Contains(strings.ToLower(l), id) {
			return true
		}
	}

	return false
}
