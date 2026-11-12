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

	"github.com/owasp-amass/amass/v5/internal/ai/semantics"
)

// LensOrgGroup asks for the corporate group of an organization: its ultimate
// parent and every organization below it. The links are the stored
// relationships the semantics table marks as one organization controlling
// another for corporate reasons (subsidiary, org_unit), so a new corporate
// relationship takes part once it is annotated. The answer is built in Go
// and never reaches the model; nothing is written.
const LensOrgGroup = "org_group"

// Group lens bounds.
const (
	groupMaxMembers = 5000
	groupMaxReads   = 40000
	// groupMaxDepth bounds the climb to the ultimate parent.
	groupMaxDepth = 32
)

// GroupMember is one organization of a corporate group and the stored
// relationship from its parent.
type GroupMember struct {
	Organization   Asset  `json:"organization"`
	ParentID       string `json:"parent_id,omitempty"`
	Label          string `json:"label,omitempty"`
	Depth          int    `json:"depth"`
	Jurisdiction   string `json:"jurisdiction,omitempty"`
	RegistrationID string `json:"registration_id,omitempty"`
}

// GroupReport is the result of the corporate group lens.
type GroupReport struct {
	// Subject is the organization the group was asked for; Domain is set
	// when it was found as an enumerated domain's main organization.
	Subject Asset  `json:"subject"`
	Domain  string `json:"domain,omitempty"`
	// Tops are the organizations with no stored parent above the subject:
	// one for a consistent group, more when sources disagree.
	Tops    []Asset       `json:"tops"`
	Members []GroupMember `json:"members"`
	Labels  []string      `json:"labels"`
	Reads   int           `json:"reads"`
	// Truncated reports that the group has more than was read.
	Truncated bool   `json:"truncated"`
	Reason    string `json:"reason,omitempty"`
}

// corporateLabels returns the relationship labels from one organization to
// another that the semantics table marks as control for corporate reasons.
func corporateLabels(t *semantics.Table) []string {
	set := map[string]bool{}
	for _, r := range t.Relations {
		if r.Source == "Organization" && r.Destination == "Organization" && r.Attribution == semantics.Controls &&
			r.Purpose == "corporate" {
			set[r.Label] = true
		}
	}

	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

type groupSearch struct {
	ctx    context.Context
	graph  Graph
	labels []string
	report GroupReport
	assets map[string]Asset
}

func (s *groupSearch) spend() bool {
	if s.report.Reads >= groupMaxReads {
		return false
	}

	s.report.Reads++
	return true
}

func (s *groupSearch) truncate(reason string) {
	if !s.report.Truncated {
		s.report.Truncated, s.report.Reason = true, reason
	}
}

func (s *groupSearch) asset(id string) (Asset, error) {
	if a, ok := s.assets[id]; ok {
		return a, nil
	}
	if !s.spend() {
		return Asset{}, errDupReadLimit
	}

	a, err := s.graph.GetAsset(s.ctx, id)
	if err == nil {
		s.assets[id] = a
	}
	return a, err
}

// links returns the corporate relationships of an organization in one
// direction, with the organization at the other end.
func (s *groupSearch) links(id, dir string) ([]Relation, error) {
	var out []Relation
	for _, label := range s.labels {
		edges, more, err := readEdges(s.ctx, s.graph, id, dir, label, groupMaxMembers, s.spend)
		if err != nil {
			return nil, err
		}
		if more {
			s.truncate(fmt.Sprintf("more than %d %s %s relationships on organization %s", groupMaxMembers, dir,
				label, id))
		}
		for _, e := range edges {
			other := e.ToID
			if dir == "in" {
				other = e.FromID
			}
			if other == id {
				continue
			}

			a, err := s.asset(other)
			if err != nil {
				return nil, err
			}
			if a.Type == "Organization" {
				out = append(out, e)
			}
		}
	}

	return out, nil
}

// FindCorporateGroup climbs from an organization to the organizations with
// no stored parent above it, then lists every organization below them,
// following the corporate relationships the semantics table defines. root
// is an Organization, or an enumerated domain's FQDN, whose main
// organization the family lens decides. It reads only.
func FindCorporateGroup(ctx context.Context, graph Graph, root Asset) (GroupReport, error) {
	table, err := relationTable()
	if err != nil {
		return GroupReport{}, err
	}

	s := &groupSearch{ctx: ctx, graph: graph, labels: corporateLabels(table), assets: map[string]Asset{}}
	s.report.Labels = s.labels
	if len(s.labels) == 0 {
		return s.report, errors.New("the semantics table defines no corporate relationships")
	}

	subject := root
	if root.Type == "FQDN" {
		family, err := FindOrganizationFamily(ctx, graph, root)
		if err != nil {
			return s.report, fmt.Errorf("main organization of %s: %w", fqdnName(root), err)
		}
		if family.Main == nil {
			return s.report, fmt.Errorf("no organization is tied to %s", fqdnName(root))
		}

		s.report.Domain = family.Domain
		subject = *family.Main
	}
	if subject.Type != "Organization" {
		return s.report, errors.New("the org-group lens starts from an organization or an enumerated domain")
	}

	s.report.Subject = subject
	s.assets[subject.ID] = subject
	tops, err := s.climb(subject)
	if err != nil && !errors.Is(err, errDupReadLimit) {
		return s.report, err
	}

	if len(tops) == 0 {
		// Every organization above the subject has a parent: the stored
		// relationships form a cycle.
		tops = []Asset{subject}
		s.truncate("the stored corporate relationships form a cycle")
	}

	s.report.Tops = tops
	if err := s.descend(tops); err != nil && !errors.Is(err, errDupReadLimit) {
		return s.report, err
	}
	if s.report.Reads >= groupMaxReads {
		s.truncate("database read limit")
	}

	return s.report, nil
}

// climb returns the organizations above subject that have no stored
// parent: the ultimate parent, or several when sources disagree.
func (s *groupSearch) climb(subject Asset) ([]Asset, error) {
	var tops []Asset
	seen := map[string]bool{subject.ID: true}
	level := []string{subject.ID}
	for depth := 0; len(level) > 0; depth++ {
		if depth >= groupMaxDepth {
			s.truncate(fmt.Sprintf("more than %d levels of parents", groupMaxDepth))
			for _, id := range level {
				tops = append(tops, s.assets[id])
			}
			break
		}

		var next []string
		for _, id := range level {
			parents, err := s.links(id, "in")
			if err != nil {
				return tops, err
			}
			if len(parents) == 0 {
				tops = append(tops, s.assets[id])
				continue
			}
			for _, e := range parents {
				if !seen[e.FromID] {
					seen[e.FromID] = true
					next = append(next, e.FromID)
				}
			}
		}
		level = next
	}

	sort.Slice(tops, func(i, j int) bool { return tops[i].ID < tops[j].ID })
	return tops, nil
}

// descend lists the tops and every organization below them, breadth first.
func (s *groupSearch) descend(tops []Asset) error {
	seen := map[string]bool{}
	type queued struct {
		id    string
		depth int
	}

	var queue []queued
	for _, t := range tops {
		seen[t.ID] = true
		s.report.Members = append(s.report.Members, s.member(t, "", "", 0))
		queue = append(queue, queued{id: t.ID})
	}
	for len(queue) > 0 {
		if err := s.ctx.Err(); err != nil {
			return err
		}

		cur := queue[0]
		queue = queue[1:]
		children, err := s.links(cur.id, "out")
		if err != nil {
			return err
		}
		sort.Slice(children, func(i, j int) bool { return children[i].ToID < children[j].ToID })
		for _, e := range children {
			if seen[e.ToID] {
				continue
			}
			if len(s.report.Members) >= groupMaxMembers {
				s.truncate(fmt.Sprintf("more than %d organizations", groupMaxMembers))
				return nil
			}

			seen[e.ToID] = true
			s.report.Members = append(s.report.Members, s.member(s.assets[e.ToID], cur.id, e.Label, cur.depth+1))
			queue = append(queue, queued{id: e.ToID, depth: cur.depth + 1})
		}
	}

	return nil
}

func (s *groupSearch) member(o Asset, parent, label string, depth int) GroupMember {
	return GroupMember{Organization: o, ParentID: parent, Label: label, Depth: depth,
		Jurisdiction: contentString(o, "jurisdiction"), RegistrationID: contentString(o, "registration_id")}
}

// FormatGroupReport renders a corporate group as an indented tree.
func FormatGroupReport(r GroupReport) string {
	var b strings.Builder
	subject := assetLabel(r.Subject)
	if r.Domain != "" {
		fmt.Fprintf(&b, "Corporate group of %s, the main organization of %s", subject, r.Domain)
	} else {
		fmt.Fprintf(&b, "Corporate group of %s", subject)
	}
	fmt.Fprintf(&b, " (%d organization(s), %d reads), from stored %s relationships.\n", len(r.Members), r.Reads,
		strings.Join(r.Labels, " and "))

	if len(r.Members) <= 1 {
		fmt.Fprintf(&b, "No parent, subsidiary or unit of %s is stored. GLEIF records parents and subsidiaries "+
			"for organizations with an LEI, and reviewed department proposals add units.\n", subject)
		return b.String()
	}
	if len(r.Tops) > 1 {
		names := make([]string, 0, len(r.Tops))
		for _, t := range r.Tops {
			names = append(names, assetLabel(t))
		}
		fmt.Fprintf(&b, "Sources disagree on the ultimate parent: %s.\n", strings.Join(names, "; "))
	} else if len(r.Tops) == 1 && r.Tops[0].ID != r.Subject.ID {
		fmt.Fprintf(&b, "Ultimate parent: %s.\n", assetLabel(r.Tops[0]))
	}

	children := map[string][]GroupMember{}
	var roots []GroupMember
	for _, m := range r.Members {
		if m.ParentID == "" {
			roots = append(roots, m)
		} else {
			children[m.ParentID] = append(children[m.ParentID], m)
		}
	}

	var write func(m GroupMember)
	write = func(m GroupMember) {
		b.WriteString(strings.Repeat("  ", m.Depth))
		if m.Label != "" {
			b.WriteString(m.Label + ": ")
		}
		b.WriteString(assetLabel(m.Organization))
		var reg []string
		for _, v := range []string{m.Jurisdiction, m.RegistrationID} {
			if v != "" {
				reg = append(reg, v)
			}
		}
		if len(reg) > 0 {
			fmt.Fprintf(&b, " [%s]", strings.Join(reg, " "))
		}
		if m.Organization.ID == r.Subject.ID {
			b.WriteString(" <- asked about")
		}
		b.WriteString("\n")
		for _, c := range children[m.Organization.ID] {
			write(c)
		}
	}
	for _, m := range roots {
		write(m)
	}

	b.WriteString("These are stored relationships, not verified ownership.")
	if r.Truncated {
		b.WriteString(" Results are partial (" + r.Reason + ").")
	}
	b.WriteString("\n")
	return b.String()
}

// orgGroupLens answers an org_group lens query.
func (a Agent) orgGroupLens(ctx context.Context, root Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := FindCorporateGroup(ctx, a.Runner.Graph, root)
	out.recordTrace(started, InvestigationTraceEvent{Stage: "org_group_lens", OutputPaths: len(report.Members),
		Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.OrgGroupReport = &report
	out.Incomplete = report.Truncated
	out.Answer = strings.TrimRight(FormatGroupReport(report), "\n")
	return out, nil
}
