// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensChanges asks what changed in what a domain or organization controls
// since a time. The answer is built in Go; nothing is written.
const LensChanges = "changes"

// ChangeGroup counts changes of one kind: assets of one type, or relations
// of one purpose.
type ChangeGroup struct {
	Key      string   `json:"key"`
	Count    int      `json:"count"`
	Examples []string `json:"examples"`
}

// ChangesReport is the result of the changes lens.
type ChangesReport struct {
	Root      graph.Asset `json:"root"`
	Owners    []string    `json:"owners,omitempty"`
	Since     time.Time   `json:"since"`
	Footprint int         `json:"footprint"`
	// LastSeen is when the subject itself was last seen; nothing can have
	// gone quiet when no enumeration has seen it since.
	LastSeen time.Time `json:"last_seen"`
	// NewAssets are controlled assets first stored since, by type, and
	// NewRelations relations of controlled assets first stored since, by
	// purpose: new names, addresses, certificates, providers, registrants.
	NewAssets    []ChangeGroup `json:"new_assets"`
	NewRelations []ChangeGroup `json:"new_relations"`
	// QuietAssets and QuietRelations were not seen again since, though the
	// subject was: removed, moved, or no longer found.
	QuietAssets    []ChangeGroup `json:"quiet_assets"`
	QuietRelations []ChangeGroup `json:"quiet_relations"`
	// Run is the latest finished collection run since then that covered the
	// subject, when one is recorded: quiet then means that run did not see
	// it.
	Run       *graph.CollectionRun `json:"run,omitempty"`
	Reads     int                  `json:"reads"`
	Truncated bool                 `json:"truncated"`
	Reason    string               `json:"reason,omitempty"`
}

var changesJSON = semantics.File("changes.json")

type changesRules struct {
	License           string `json:"_license"`
	About             string `json:"_about"`
	DefaultWindowDays int    `json:"default_window_days"`
	Examples          int    `json:"examples"`
}

var loadChangesRules = sync.OnceValue(func() changesRules {
	var r changesRules
	if err := graph.DecodeStrict(changesJSON, &r); err != nil {
		panic("changes.json: " + err.Error())
	}
	if r.DefaultWindowDays < 1 || r.Examples < 1 {
		panic("changes.json: default_window_days and examples must be positive")
	}

	return r
})

// changesNow is the clock the default window ends at; tests replace it.
var changesNow = time.Now

// DefaultChangesSince is the start of the window a question without a time
// covers.
func DefaultChangesSince() time.Time {
	return changesNow().AddDate(0, 0, -loadChangesRules().DefaultWindowDays)
}

// FindChanges walks the controlled footprint of a domain or organization, as
// the vendors lens does, and compares it with since using the times each
// asset and relation was first stored and last seen: what appeared since,
// and what was not seen again since though the subject was. A zero since
// means the default window. It reads only.
func FindChanges(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset, since time.Time,
	limits LensLimits) (ChangesReport, error) {
	if since.IsZero() {
		since = DefaultChangesSince()
	}
	out := ChangesReport{Root: root, Since: since, LastSeen: root.LastSeen}
	meaning := graph.MeaningsOf(schema)
	if schema == nil || meaning == nil {
		return out, errors.New("the changes lens requires relationship semantics")
	}
	bounded, ok := g.(graph.BoundedGraph)
	if !ok {
		return out, errors.New("bounded graph reader required")
	}
	if err := limits.Validate(); err != nil {
		return out, err
	}

	report := ThirdPartyReport{Root: root, FootprintTypes: map[string]int{}}
	w := newLensWalker(ctx, g, bounded, meaning, schema.Relations(), root, &report)
	w.limit(limits)
	roots := []graph.Asset{root}
	owners, err := w.owningOrganizations(root)
	if err != nil {
		return out, err
	}
	for _, o := range owners {
		out.Owners = append(out.Owners, graph.AssetLabel(o))
		roots = append(roots, o)
		if o.LastSeen.After(out.LastSeen) {
			out.LastSeen = o.LastSeen
		}
	}

	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return out, err
	}
	out.Footprint = len(owned)

	// Something is quiet only if the subject was seen after since and the
	// thing was not; a day's margin keeps one enumeration's own spread of
	// times from counting. A recorded run that covered the subject makes it
	// exact: what it did not see is quiet.
	quietBefore := since
	seenSince := out.LastSeen.After(since.Add(24 * time.Hour))
	run, err := coveringRun(ctx, g, roots, since)
	if err != nil {
		return out, err
	}
	if run != nil {
		out.Run = run
		quietBefore, seenSince = run.StartedAt, true
	}

	c := changeTally{examples: loadChangesRules().Examples, groups: map[string]map[string]*ChangeGroup{}}
	for _, id := range order {
		a := owned[id]
		label := graph.AssetLabel(a)
		if a.CreatedAt.After(since) {
			c.add("new_assets", a.Type, label)
		} else if seenSince && !a.LastSeen.IsZero() && a.LastSeen.Before(quietBefore) {
			c.add("quiet_assets", a.Type, label)
		}
	}

	seenEdge := map[string]bool{}
	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if w.outOfReads() {
			w.truncate("database read limit")
			break
		}

		a := owned[id]
		steps, err := w.steps(a)
		if err != nil {
			return out, err
		}
		for _, s := range steps {
			if seenEdge[s.edge.ID] {
				continue
			}
			seenEdge[s.edge.ID] = true

			from, to := a, s.other
			if !s.forward {
				from, to = s.other, a
			}
			key := s.purpose
			if key == "" {
				key = s.edge.Label
			}
			example := fmt.Sprintf("%s --%s--> %s", graph.AssetLabel(from), s.edge.Label, graph.AssetLabel(to))
			switch {
			case s.edge.CreatedAt.After(since):
				c.add("new_relations", key, example)
			case seenSince && !s.edge.LastSeen.IsZero() && s.edge.LastSeen.Before(quietBefore):
				c.add("quiet_relations", key, example)
			}
		}
	}

	out.NewAssets, out.QuietAssets = c.list("new_assets"), c.list("quiet_assets")
	out.NewRelations, out.QuietRelations = c.list("new_relations"), c.list("quiet_relations")
	out.Reads = report.Reads
	out.Truncated, out.Reason = report.Truncated, report.Reason
	return out, nil
}

type changeTally struct {
	examples int
	groups   map[string]map[string]*ChangeGroup
}

func (c *changeTally) add(kind, key, example string) {
	if c.groups[kind] == nil {
		c.groups[kind] = map[string]*ChangeGroup{}
	}
	g, ok := c.groups[kind][key]
	if !ok {
		g = &ChangeGroup{Key: key}
		c.groups[kind][key] = g
	}
	g.Count++
	if len(g.Examples) < c.examples {
		graph.AddUnique(&g.Examples, example)
	}
}

func (c *changeTally) list(kind string) []ChangeGroup {
	var out []ChangeGroup
	for _, g := range c.groups[kind] {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// coveringRun returns the latest finished collection run started after since
// whose scope covers one of roots: names it, or names a domain one of them
// is a name under. It returns nil when none is recorded or the graph does
// not record runs.
func coveringRun(ctx context.Context, g graph.Graph, roots []graph.Asset, since time.Time) (*graph.CollectionRun, error) {
	rr, ok := g.(graph.RunReader)
	if !ok {
		return nil, nil
	}

	runs, err := rr.CollectionRuns(ctx, since, changesRunsRead)
	if errors.Is(err, graph.ErrUnsupported) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	for _, run := range runs {
		if run.Status != graph.RunFinished || !run.StartedAt.After(since) {
			continue
		}
		for _, t := range run.Scope {
			for _, r := range roots {
				if runCovers(t, r) {
					found := run
					return &found, nil
				}
			}
		}
	}

	return nil, nil
}

// changesRunsRead bounds the runs the changes lens reads.
const changesRunsRead = 200

func runCovers(t graph.RunTarget, a graph.Asset) bool {
	if strings.EqualFold(t.Type, a.Type) && strings.EqualFold(strings.TrimSuffix(t.Key,
		"."), strings.TrimSuffix(a.Key, ".")) {
		return true
	}
	if t.Type != "FQDN" || a.Type != "FQDN" {
		return false
	}

	name := strings.ToLower(strings.TrimSuffix(graph.FQDNName(a), "."))
	domain := strings.ToLower(strings.TrimSuffix(t.Key, "."))
	return domain != "" && strings.HasSuffix(name, "."+domain)
}

// FormatChangesReport renders the changes lens for a terminal.
func FormatChangesReport(r ChangesReport) string {
	var b strings.Builder
	scope := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		scope += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Changes to %s since %s, across %d controlled asset(s) (%d reads).\n", scope,
		r.Since.Format("2006-01-02"), r.Footprint, r.Reads)

	write := func(title, unit string, groups []ChangeGroup) {
		if len(groups) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", title)
		for _, g := range groups {
			fmt.Fprintf(&b, "  %s: %d %s, e.g. %s\n", g.Key, g.Count, unit, strings.Join(g.Examples, "; "))
		}
	}
	write("First stored since then (assets, by type)", "new", r.NewAssets)
	write("First stored since then (relationships, by purpose)", "new", r.NewRelations)
	if r.Run != nil {
		fmt.Fprintf(&b, "\nCompared with the %s run that started %s and covered it", r.Run.Tool,
			r.Run.StartedAt.Format("2006-01-02 15:04"))
		if r.Run.ExternalID != "" {
			fmt.Fprintf(&b, " (%s)", r.Run.ExternalID)
		}

		b.WriteString(".\n")
		write("Not seen by that run (assets, by type)", "quiet", r.QuietAssets)
		write("Not seen by that run (relationships, by purpose)", "quiet", r.QuietRelations)
	} else if r.LastSeen.After(r.Since.Add(24 * time.Hour)) {
		write("Not seen again since then (assets, by type)", "quiet", r.QuietAssets)
		write("Not seen again since then (relationships, by purpose)", "quiet", r.QuietRelations)
	} else {
		fmt.Fprintf(&b, "\nNo enumeration has seen it since %s, so nothing can be said to have gone quiet.\n",
			r.Since.Format("2006-01-02"))
	}
	if len(r.NewAssets)+len(r.NewRelations)+len(r.QuietAssets)+len(r.QuietRelations) == 0 {
		b.WriteString("Nothing changed in the stored records.\n")
	}

	b.WriteString("These compare when records were first stored and last seen; " +
		"quiet means not observed again, not proven removed.")
	if r.Truncated {
		fmt.Fprintf(&b, " Results are partial (%s)%s", r.Reason, partialAdvice(r.Reason))
	}
	b.WriteString("\n")
	return b.String()
}
