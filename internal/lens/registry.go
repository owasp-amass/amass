// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// Report is the result of a registered subject lens.
type Report interface {
	// Text renders the report for a terminal.
	Text() string
	// Facts are short lines naming what the report found, for evaluations
	// to match answers against.
	Facts() []string
	// Partial reports whether a limit cut the report short, and which.
	Partial() (bool, string)
}

// Options are what a subject lens may be given besides its subject.
type Options struct {
	Limits LensLimits
	// Since starts the window of lenses that compare with an earlier time;
	// zero means their default.
	Since time.Time
	// Other is the second subject of a lens that compares two.
	Other graph.Asset
}

// SubjectLens is a lens answered from a domain or organization alone.
// Registering one in SubjectLenses makes it an amass lens command and,
// unless it needs a second subject, an answer kind for questions.
type SubjectLens struct {
	// Name is the answer kind; Command the amass lens command.
	Name    string
	Command string
	// Description and Examples tell the question planner when to choose it.
	// They are kept short: every planner prompt carries them.
	Description string
	Examples    []string
	// NeedsOther marks a lens that compares the subject with a second one,
	// which only amass lens can name.
	NeedsOther bool
	Find       func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error)
}

// SubjectLenses lists the registered subject lenses.
func SubjectLenses() []SubjectLens {
	return []SubjectLens{
		subdomainsLens,
		servicesLens,
		networkLens,
		danglingLens,
		changesLens,
		vulnerableLens,
		lookalikesLens,
		certificatesLens,
		domainsLens,
		emailLens,
		exposureLens,
		concentrationLens,
		coverageLens,
		geographyLens,
		compareLens,
		reportLens,
	}
}

// SubjectLensNamed returns the registered lens with an answer kind or
// command name.
func SubjectLensNamed(name string) (SubjectLens, bool) {
	for _, l := range SubjectLenses() {
		if l.Name == name || l.Command == name {
			return l, true
		}
	}

	return SubjectLens{}, false
}

// scope is the controlled footprint of a domain or organization that most
// lenses start from, with the walker that read it.
type scope struct {
	w      *lensWalker
	report *ThirdPartyReport
	root   graph.Asset
	owners []graph.Asset
	owned  map[string]graph.Asset
	order  []string
	// ownDomains are the registered domains of the footprint's names, and
	// ownNets its netblocks.
	ownDomains map[string]bool
	ownNets    []netip.Prefix
}

// newScope walks the controlled footprint of root and the organizations
// that own it, as the vendors lens does.
func newScope(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset, limits LensLimits,
	name string) (*scope, error) {
	meaning := graph.MeaningsOf(schema)
	if schema == nil || meaning == nil {
		return nil, errors.New("the " + name + " lens requires relationship semantics")
	}

	bounded, ok := g.(graph.BoundedGraph)
	if !ok {
		return nil, errors.New("bounded graph reader required")
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}

	s := &scope{root: root, report: &ThirdPartyReport{Root: root, FootprintTypes: map[string]int{}},
		ownDomains: map[string]bool{}}
	s.w = newLensWalker(ctx, g, bounded, meaning, schema.Relations(), root, s.report)
	s.w.maxAssets, s.w.maxReads = limits.assets(), limits.reads()
	if targets := lensFocus(name); len(targets) > 0 {
		s.w.admitOnly = footprintFocusTypes(s.w.relations, meaning, targets)
		s.w.expand = s.w.admitOnly
	}

	roots := []graph.Asset{root}
	owners, err := s.w.owningOrganizations(root)
	if err != nil {
		return nil, err
	}

	s.owners = owners
	roots = append(roots, owners...)

	s.owned, s.order, err = s.w.controlledFootprint(roots)
	if err != nil {
		return nil, err
	}
	for _, id := range s.order {
		a := s.owned[id]
		switch a.Type {
		case "FQDN":
			s.ownDomains[graph.RegisteredDomain(graph.FQDNName(a))] = true
		case "Netblock":
			if p, err := netip.ParsePrefix(graph.ContentString(a, "cidr")); err == nil {
				s.ownNets = append(s.ownNets, p.Masked())
			}
		}
	}

	return s, nil
}

// ownerNames are the labels of the organizations that own the root.
func (s *scope) ownerNames() []string {
	var out []string
	for _, o := range s.owners {
		out = append(out, graph.AssetLabel(o))
	}

	return out
}

// spent reports whether the read budget is used up, marking the report
// partial when it is.
func (s *scope) spent() bool {
	if err := s.w.ctx.Err(); err != nil {
		s.w.truncate(err.Error())
		return true
	}
	if s.report.Reads >= s.w.maxReads {
		s.w.truncate("database read limit")
		return true
	}

	return false
}

// party names who controls a, as the vendors lens does: its organization,
// the operator of its network or its domain. own is set when it is the
// subject.
func (s *scope) party(a graph.Asset) (string, string, bool, error) {
	d := dependencyScan{w: s.w, owned: s.owned, ownDomains: s.ownDomains, ownNets: s.ownNets}
	name, id, own, _, err := d.party(a)
	return name, id, own, err
}

// subject names the root and its owners for a report heading.
func (s *scope) subject() string {
	label := graph.AssetLabel(s.root)
	for i, o := range s.ownerNames() {
		if i == 0 {
			label += " and " + o
		} else {
			label += ", " + o
		}
	}

	return label
}

// lensBase is what every scoped report carries.
type lensBase struct {
	Root      graph.Asset `json:"root"`
	Owners    []string    `json:"owners,omitempty"`
	Footprint int         `json:"footprint"`
	Reads     int         `json:"reads"`
	Truncated bool        `json:"truncated"`
	Reason    string      `json:"reason,omitempty"`
}

func (s *scope) base() lensBase {
	return lensBase{Root: s.root, Owners: s.ownerNames(), Footprint: len(s.owned), Reads: s.report.Reads,
		Truncated: s.report.Truncated, Reason: s.report.Reason}
}

// Partial implements Report.
func (b lensBase) Partial() (bool, string) { return b.Truncated, b.Reason }

// partialNote ends a report's text with the limit that cut it short.
func (b lensBase) partialNote() string {
	if !b.Truncated {
		return ""
	}

	return " Results are partial (" + b.Reason + "); raise -max-assets or -max-reads to cover more."
}
