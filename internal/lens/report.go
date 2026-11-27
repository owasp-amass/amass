// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensReport assembles an attack surface report from the other lenses.
const LensReport = "report"

var reportLens = SubjectLens{
	Name:    LensReport,
	Command: "report",
	Description: "Write an attack surface report for a domain or organization: key findings first (takeovers, " +
		"exposed services, unsupported software, expired domains and certificates, email spoofing), then each " +
		"lens's results. Read-only",
	Examples: []string{
		"Write an attack surface report for <domain>",
		"Summarize the security posture of <organization>",
	},
}

// The report runs the other registered lenses, so its Find is set once the
// registry exists.
func init() {
	reportLens.Find = func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindReport(ctx, g, schema, root, opts.Limits)
	}
}

var reportJSON = semantics.File("report.json")

type reportSectionRule struct {
	Lens  string `json:"lens"`
	Title string `json:"title"`
}

type reportFindingRule struct {
	Lens     string `json:"lens"`
	Kind     string `json:"kind"`
	AnyWord  bool   `json:"any_word,omitempty"`
	Title    string `json:"title"`
	Priority int    `json:"priority"`
}

type reportRules struct {
	License  string              `json:"_license"`
	About    string              `json:"_about"`
	Examples int                 `json:"examples_per_finding"`
	Sections []reportSectionRule `json:"sections"`
	Findings []reportFindingRule `json:"findings"`
}

var loadReportRules = sync.OnceValue(func() reportRules {
	var r reportRules
	if err := graph.DecodeStrict(reportJSON, &r); err != nil {
		panic("report.json: " + err.Error())
	}
	if r.Examples < 1 || len(r.Sections) == 0 {
		panic("report.json: examples_per_finding and sections are required")
	}

	return r
})

// sectionFinder runs one lens for the report.
type sectionFinder func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (Report, error)

// textReport adapts a lens that has a text form but no Report.
type textReport struct {
	text, reason string
	facts        []string
	partial      bool
}

func (t textReport) Text() string { return t.text }

func (t textReport) Facts() []string { return t.facts }

func (t textReport) Partial() (bool, string) { return t.partial, t.reason }

// reportSection finds the registered subject lens a section names.
func reportSection(name string) (sectionFinder, bool) {
	if l, ok := SubjectLensNamed(name); ok && !l.NeedsOther && l.Name != LensReport {
		return func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
			limits LensLimits) (Report, error) {
			return l.Find(ctx, g, schema, root, Options{Limits: limits})
		}, true
	}

	return nil, false
}

// ReportSection is one lens's part of the report.
type ReportSection struct {
	Lens    string `json:"lens"`
	Title   string `json:"title"`
	Text    string `json:"text"`
	Partial string `json:"partial,omitempty"`
	Error   string `json:"error,omitempty"`
}

// KeyFinding is a kind of finding worth attention, with examples.
type KeyFinding struct {
	Lens     string   `json:"lens"`
	Kind     string   `json:"kind"`
	Title    string   `json:"title"`
	Priority int      `json:"priority"`
	Count    int      `json:"count"`
	Examples []string `json:"examples"`
}

// SurfaceReport is the result of the report lens.
type SurfaceReport struct {
	Root     graph.Asset     `json:"root"`
	Date     time.Time       `json:"date"`
	Findings []KeyFinding    `json:"findings"`
	Sections []ReportSection `json:"sections"`
}

// reportNow is the date a report carries.
var reportNow = time.Now

// FindReport runs the report's lenses over one read of the subject's
// footprint and collects their key findings. A lens that fails is noted in
// its section; the others still run. It reads only.
func FindReport(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (SurfaceReport, error) {
	rules := loadReportRules()
	g = graph.Cached(g)
	out := SurfaceReport{Root: root, Date: reportNow()}
	found := map[[2]string]*KeyFinding{}

	for _, sec := range rules.Sections {
		if err := ctx.Err(); err != nil {
			return out, err
		}

		find, ok := reportSection(sec.Lens)
		if !ok {
			return out, fmt.Errorf("report.json names an unknown lens %q", sec.Lens)
		}

		part := ReportSection{Lens: sec.Lens, Title: sec.Title}
		r, err := find(ctx, g, schema, root, limits)
		if err != nil {
			part.Error = err.Error()
			out.Sections = append(out.Sections, part)
			continue
		}

		part.Text = strings.TrimSpace(r.Text())
		if partial, why := r.Partial(); partial {
			part.Partial = why
		}

		out.Sections = append(out.Sections, part)

		for _, fact := range r.Facts() {
			words := strings.Fields(fact)
			if len(words) == 0 {
				continue
			}
			for _, fr := range rules.Findings {
				if fr.Lens != sec.Lens || (words[0] != fr.Kind && !(fr.AnyWord && slices.Contains(words, fr.Kind))) {
					continue
				}

				key := [2]string{fr.Lens, fr.Kind}
				kf := found[key]
				if kf == nil {
					kf = &KeyFinding{Lens: fr.Lens, Kind: fr.Kind, Title: fr.Title, Priority: fr.Priority}
					found[key] = kf
				}

				kf.Count++
				example := strings.TrimSpace(strings.TrimPrefix(fact, fr.Kind))
				if fr.AnyWord {
					example = fact
				}
				if len(kf.Examples) < rules.Examples && example != "" {
					graph.AddUnique(&kf.Examples, example)
				}

				break
			}
		}
	}

	for _, kf := range found {
		out.Findings = append(out.Findings, *kf)
	}

	sort.Slice(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}

		return a.Title < b.Title
	})
	return out, nil
}

// Text implements Report: the report in Markdown.
func (r SurfaceReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Attack surface report: %s\n\n", graph.AssetLabel(r.Root))
	fmt.Fprintf(&b, "_Computed %s from the Amass Asset Database: what past enumerations stored, not a live "+
		"scan._\n\n", r.Date.Format("2006-01-02"))

	b.WriteString("## Key findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("Nothing stored falls in a key finding category.\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "- **%s** (%d)", f.Title, f.Count)
		if len(f.Examples) > 0 {
			fmt.Fprintf(&b, ": %s", strings.Join(f.Examples, "; "))
			if f.Count > len(f.Examples) {
				b.WriteString("; ...")
			}
		}

		b.WriteString("\n")
	}

	var partial []string
	for _, s := range r.Sections {
		fmt.Fprintf(&b, "\n## %s\n\n", s.Title)
		switch {
		case s.Error != "":
			fmt.Fprintf(&b, "This section could not be computed: %s\n", s.Error)
		default:
			b.WriteString("```text\n" + s.Text + "\n```\n")
		}
		if s.Partial != "" {
			partial = append(partial, s.Title)
		}
	}
	if len(partial) > 0 {
		fmt.Fprintf(&b, "\n_Partial sections (a read limit was reached): %s. Raise the limits to cover more._\n",
			strings.Join(partial, ", "))
	}

	return b.String()
}

// Facts implements Report.
func (r SurfaceReport) Facts() []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, fmt.Sprintf("%s %s %d", f.Lens, f.Kind, f.Count))
	}

	return out
}

// Partial implements Report.
func (r SurfaceReport) Partial() (bool, string) {
	for _, s := range r.Sections {
		if s.Partial != "" {
			return true, s.Partial
		}
	}

	return false, ""
}
