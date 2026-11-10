// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// LensTable builds a table from the subject's controlled assets: one row
// per controlled asset of the single target type, and one column per
// TableColumn. Like the other lenses it is answered in Go from the
// relationship semantics table.
const LensTable = "table"

// Column roles.
const (
	// ColumnReached is the nearest asset of the column type reached from
	// the previous cell through same_subject or infrastructure edges.
	ColumnReached = ""
	// ColumnController is the party that controls or operates the previous
	// cell's asset, such as the hosting provider of an IP address.
	ColumnController = "controller"
)

// Table bounds.
const (
	tableMaxColumns  = 5
	tableMaxCell     = 5
	tableReachDepth  = 3
	tableOwnedSuffix = " (self)"
)

// TableColumn is one column of a table answer. Columns form a chain: the
// first is derived from the row asset and each later one from the previous
// column's assets.
type TableColumn struct {
	Type string `json:"type"`
	Role string `json:"role"`
}

// TableReport is the result of the table lens.
type TableReport struct {
	Root    Asset      `json:"root"`
	Owners  []string   `json:"owners,omitempty"`
	RowType string     `json:"row_type"`
	Headers []string   `json:"headers"`
	Rows    [][]string `json:"rows"`
	// Witness holds, for each row, the stored edges that attribute the row
	// asset to the subject and support its cells.
	Witness   [][]WitnessEdge `json:"witness,omitempty"`
	Reads     int             `json:"reads"`
	Truncated bool            `json:"truncated"`
	Reason    string          `json:"reason,omitempty"`
}

// validateColumns checks a column chain against the asset types in the
// catalog.
func validateColumns(columns []TableColumn, types map[string]bool) error {
	if len(columns) == 0 || len(columns) > tableMaxColumns {
		return fmt.Errorf("a table needs 1..%d columns", tableMaxColumns)
	}
	for i, c := range columns {
		switch c.Role {
		case ColumnReached:
			if !types[c.Type] {
				return fmt.Errorf("column %d: unknown OAM type %q", i+1, c.Type)
			}
			if i > 0 && columns[i-1] == c {
				return fmt.Errorf("column %d repeats column %d", i+1, i)
			}
		case ColumnController:
			if c.Type != "Organization" {
				return fmt.Errorf("column %d: a controller column has type Organization", i+1)
			}
			if i > 0 && columns[i-1].Role == ColumnController {
				return fmt.Errorf("column %d: a controller column names who controls the asset in the column "+
					"before it, so two in a row repeat the same organization. Give each asset the question asks "+
					"about its own column first, e.g. [{\"type\":\"IPAddress\",\"role\":\"\"},"+
					"{\"type\":\"Organization\",\"role\":\"controller\"}] for an IP address and its hosting "+
					"provider", i+1)
			}
		default:
			return fmt.Errorf("column %d: role must be \"\" or %q", i+1, ColumnController)
		}
	}

	return nil
}

// reach returns the nearest assets of kind from a, following same_subject
// edges (except the hierarchy) in either direction and infrastructure edges
// forward, up to tableReachDepth. It never crosses ownership or third
// parties, so a URL reaches its IP address through its domain name and
// that name's DNS records.
func (w *lensWalker) reach(a Asset, kind string) ([]Asset, map[string][]WitnessEdge, error) {
	if a.Type == kind {
		return []Asset{a}, map[string][]WitnessEdge{a.ID: nil}, nil
	}

	links := controller{links: map[string]link{}}
	seen := map[string]bool{a.ID: true}
	frontier := []Asset{a}
	for depth := 0; depth < tableReachDepth && len(frontier) > 0; depth++ {
		var next, found []Asset
		for _, cur := range frontier {
			steps, err := w.steps(cur)
			if err != nil {
				return nil, nil, err
			}
			for _, s := range steps {
				pass := (s.attr == attrSameSubject && s.purpose != purposeHierarchy) ||
					(s.attr == attrInfrastructure && s.forward)
				if seen[s.other.ID] || !pass {
					continue
				}

				seen[s.other.ID] = true
				links.links[s.other.ID] = link{parent: cur, edge: s.edge}
				if s.other.Type == kind {
					found = append(found, s.other)
					continue
				}

				next = append(next, s.other)
			}
		}
		if len(found) > 0 {
			sort.Slice(found, func(i, j int) bool { return assetLabel(found[i]) < assetLabel(found[j]) })
			witness := map[string][]WitnessEdge{}
			for _, f := range found {
				witness[f.ID] = links.witness(f.ID, w.assets)
			}

			return found, witness, nil
		}

		frontier = next
	}

	return nil, nil, nil
}

// searchTable runs the table lens from root.
func searchTable(ctx context.Context, graph Graph, schema SchemaCatalog, root Asset, rowType string, columns []TableColumn, limit int) (TableReport, error) {
	report := TableReport{Root: root, RowType: rowType, Headers: []string{typePlural(rowType)}, Rows: [][]string{}}
	meaning := meaningsOf(schema)
	if schema == nil || meaning == nil {
		return report, errors.New("the table lens requires relationship semantics")
	}

	bounded, ok := graph.(BoundedGraph)
	if !ok {
		return report, errors.New("bounded graph reader required")
	}

	counters := &ThirdPartyReport{}
	w := newLensWalker(ctx, graph, bounded, meaning, schema.Relations(), root, counters)
	w.expand = footprintExpansionTypes(w.relations, meaning, []string{rowType})
	w.parent, w.via = map[string]string{}, map[string]Relation{}
	roots := []Asset{root}
	owners, err := w.owningOrganizations(root)
	if err != nil {
		return report, err
	}
	for _, o := range owners {
		report.Owners = append(report.Owners, assetLabel(o))
		roots = append(roots, o)
	}

	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return report, err
	}
	for _, c := range columns {
		header := typePlural(c.Type)
		if c.Role == ColumnController {
			header = "Controlling organization"
		}

		report.Headers = append(report.Headers, header)
	}

	self := assetLabel(root)
	if root.Type != "Organization" && len(owners) > 0 {
		self = assetLabel(owners[0])
	}

	d := dependencyScan{w: w, owned: owned, ownDomains: map[string]bool{}, self: self}
	for _, a := range owned {
		if a.Type == "FQDN" {
			d.ownDomains[registeredDomain(fqdnName(a))] = true
		}
	}

	seenRow := map[string]bool{}
	for _, id := range order {
		row := owned[id]
		if row.Type != rowType || id == root.ID || seenRow[assetLabel(row)] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if len(report.Rows) >= limit {
			counters.Truncated, counters.Reason = true, "row limit"
			break
		}

		seenRow[assetLabel(row)] = true
		cells, witness, err := d.tableRow(row, columns)
		if err != nil {
			return report, err
		}

		report.Witness = append(report.Witness, append(pathWitness(w.path(id, owned)), witness...))
		report.Rows = append(report.Rows, append([]string{assetLabel(row)}, cells...))
	}

	byLabel := make([]int, len(report.Rows))
	for i := range byLabel {
		byLabel[i] = i
	}

	sort.SliceStable(byLabel, func(i, j int) bool { return report.Rows[byLabel[i]][0] < report.Rows[byLabel[j]][0] })
	rows, witness := make([][]string, len(byLabel)), make([][]WitnessEdge, len(byLabel))
	for i, k := range byLabel {
		rows[i], witness[i] = report.Rows[k], report.Witness[k]
	}

	report.Rows, report.Witness = rows, witness
	report.Reads, report.Truncated, report.Reason = counters.Reads, counters.Truncated, counters.Reason
	return report, nil
}

// tableRow fills the column chain for one row asset.
func (d dependencyScan) tableRow(row Asset, columns []TableColumn) ([]string, []WitnessEdge, error) {
	cells := make([]string, 0, len(columns))
	var witness []WitnessEdge
	current := []Asset{row}
	for _, c := range columns {
		var next []Asset
		var labels []string
		seen := map[string]bool{}
		for _, a := range current {
			if c.Role == ColumnController {
				name, _, own, chain, err := d.party(a)
				if err != nil {
					return nil, nil, err
				}
				if own {
					name = d.self + tableOwnedSuffix
				}
				if name != "" && !seen[name] {
					seen[name] = true
					labels = append(labels, name)
					witness = append(witness, chain...)
				}

				continue
			}

			found, chains, err := d.w.reach(a, c.Type)
			if err != nil {
				return nil, nil, err
			}
			for _, f := range found {
				if !seen[f.ID] && len(next) < tableMaxCell {
					seen[f.ID] = true
					next = append(next, f)
					labels = append(labels, assetLabel(f))
					witness = append(witness, chains[f.ID]...)
				}
			}
		}

		cells = append(cells, strings.Join(labels, ", "))
		if c.Role != ColumnController {
			current = next
		}
	}

	return cells, witness, nil
}

// tableAnswer renders a TableReport as a plain-text table.
func tableAnswer(r TableReport) string {
	var b strings.Builder
	subject := assetLabel(r.Root) + " (" + r.Root.Type + ")"
	if len(r.Rows) == 0 {
		fmt.Fprintf(&b, "No %s are documented as controlled by %s.", typePlural(r.RowType), subject)
		return b.String()
	}

	fmt.Fprintf(&b, "%d %s controlled by %s", len(r.Rows), typePlural(r.RowType), subject)
	if len(r.Owners) > 0 {
		fmt.Fprintf(&b, " or its registrant %s", strings.Join(r.Owners, ", "))
	}

	b.WriteString(":\n\n| " + strings.Join(r.Headers, " | ") + " |\n|")
	for range r.Headers {
		b.WriteString(" --- |")
	}

	b.WriteString("\n")
	for _, row := range r.Rows {
		cells := make([]string, len(row))
		for i, c := range row {
			cells[i] = c
			if c == "" {
				cells[i] = "-"
			}
		}

		b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
	}

	b.WriteString("\nCells come from stored OAM relationships (DNS records, registrations, network announcements); " +
		"\"-\" means none is recorded. They are not verified current resolution or contracts.")
	if r.Truncated {
		b.WriteString(" Results are partial (" + r.Reason + ").")
	}

	return b.String()
}

// tableLens answers a table lens query from root.
func (a Agent) tableLens(ctx context.Context, root Asset, q Query, opts AdaptiveOptions, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := searchTable(ctx, a.Runner.Graph, a.Runner.Catalog, root, q.TargetTypes[0], q.Columns,
		inventoryLimit(opts))
	out.recordTrace(started, InvestigationTraceEvent{Stage: "table_lens", OutputPaths: len(report.Rows),
		Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.TableReport = &report
	out.Incomplete = report.Truncated
	out.Answer = tableAnswer(report)
	return out, nil
}

// collapseRepeatedColumns drops a column identical to the one before it,
// such as a second "controlling organization" column, which would only
// repeat the same cells. Planner goals are normalized this way before
// validation; structured callers get the validation error instead.
func collapseRepeatedColumns(columns []TableColumn) []TableColumn {
	var out []TableColumn
	for i, c := range columns {
		if i > 0 && c == columns[i-1] {
			continue
		}

		out = append(out, c)
	}

	return out
}
