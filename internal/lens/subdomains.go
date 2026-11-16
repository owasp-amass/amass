// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensSubdomains asks for the names a domain or organization controls, each
// with the addresses it resolves to, and how those names distribute across
// autonomous systems and netblocks. The answer is built in Go from stored
// records; nothing is written and no live resolution is done.
const LensSubdomains = "subdomains"

// subdomainsExamples bounds the example names kept per summary group.
const subdomainsExamples = 3

var subdomainsLens = SubjectLens{
	Name:    LensSubdomains,
	Command: "subdomains",
	Description: "List the subdomains (FQDNs) a domain or organization controls, each with its stored IP addresses, " +
		"and a summary of how many names fall into each autonomous system and netblock. Read-only",
	Examples: []string{"List the subdomains of <domain>", "Which names does <organization> have and where do they resolve?",
		"How many of <domain>'s names are in each netblock?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindSubdomains(ctx, g, schema, root, opts.Limits)
	},
}

// SubdomainName is one controlled name, the DNS record types stored for it,
// and the addresses it resolves to.
type SubdomainName struct {
	Name string `json:"name"`
	// Records are the DNS record types stored for the name (A, MX, TXT and
	// so on), sorted. An empty list means the name was discovered but no DNS
	// record was verified for it.
	Records []string `json:"records,omitempty"`
	// Aliases are the names a CNAME chain points through, in order, so the
	// raw target is shown rather than only the addresses it resolves to.
	Aliases   []string `json:"aliases,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	// Aliased marks a name whose addresses are reached through a CNAME
	// chain rather than stored on the name itself.
	Aliased bool `json:"aliased,omitempty"`
}

// SubdomainsReport is the result of the subdomains lens.
type SubdomainsReport struct {
	lensBase
	// Names are the controlled names, sorted. WithRecords counts those that
	// have at least one stored DNS record, Resolving those with at least one
	// stored address, and DiscoveredOnly those that were discovered but have
	// no stored DNS record at all.
	Names          []SubdomainName `json:"names"`
	WithRecords    int             `json:"with_records"`
	Resolving      int             `json:"resolving"`
	DiscoveredOnly int             `json:"discovered_only"`
	// ByAutonomousSystem and ByNetblock count the names whose addresses fall
	// into each, most names first.
	ByAutonomousSystem []ChangeGroup `json:"by_autonomous_system,omitempty"`
	ByNetblock         []ChangeGroup `json:"by_netblock,omitempty"`
}

// asInfo is an autonomous system's number and name, cached per run.
type asInfo struct {
	number string
	name   string
}

// subScan resolves each controlled name and tallies the names by autonomous
// system and netblock.
type subScan struct {
	s      *scope
	byAS   map[string]*ChangeGroup
	byNet  map[string]*ChangeGroup
	asOrd  []string
	netOrd []string
	asOf   map[string]asInfo
}

// FindSubdomains lists the names a domain or organization controls with
// their stored addresses, and summarizes the names by autonomous system and
// netblock. It reads only.
func FindSubdomains(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (SubdomainsReport, error) {
	g = graph.Cached(g)
	var out SubdomainsReport
	s, err := newScope(ctx, g, schema, root, limits, LensSubdomains)
	if err != nil {
		return out, err
	}

	sc := &subScan{s: s, byAS: map[string]*ChangeGroup{}, byNet: map[string]*ChangeGroup{}, asOf: map[string]asInfo{}}
	for _, id := range s.order {
		if s.spent() {
			break
		}

		name := s.owned[id]
		if name.Type != "FQDN" {
			continue
		}

		entry, err := sc.resolve(name)
		if err != nil {
			return out, err
		}

		out.Names = append(out.Names, entry)
		if len(entry.Records) > 0 {
			out.WithRecords++
		} else {
			out.DiscoveredOnly++
		}
		if len(entry.Addresses) > 0 {
			out.Resolving++
		}
	}

	sort.Slice(out.Names, func(i, j int) bool { return out.Names[i].Name < out.Names[j].Name })
	out.ByAutonomousSystem = sc.groups(sc.byAS, sc.asOrd)
	out.ByNetblock = sc.groups(sc.byNet, sc.netOrd)
	out.lensBase = s.base()
	return out, nil
}

// resolve follows a name's stored records to its addresses and tallies the
// name under each address's netblock and autonomous system.
func (sc *subScan) resolve(name graph.Asset) (SubdomainName, error) {
	entry := SubdomainName{Name: graph.FQDNName(name)}

	records, err := recordTypesOf(sc.s.w, name)
	if err != nil {
		return entry, err
	}
	entry.Records = records

	res, err := resolveName(sc.s.w, name)
	if err != nil {
		return entry, err
	}

	entry.Aliased = res.Aliased()
	for _, alias := range res.Aliases {
		graph.AddUnique(&entry.Aliases, graph.FQDNName(alias))
	}

	countedAS := map[string]bool{}
	countedNet := map[string]bool{}
	for _, addr := range res.Addresses {
		ip := graph.ContentString(addr, "address")
		if ip == "" {
			ip = graph.AssetLabel(addr)
		}

		graph.AddUnique(&entry.Addresses, ip)

		block, err := sc.blockOf(addr)
		if err != nil {
			return entry, err
		}

		netKey := "(no stored netblock)"
		asKey := "(no stored autonomous system)"
		if block.ID != "" {
			netKey = graph.ContentString(block, "cidr")
			info, err := sc.autonomousSystem(block)
			if err != nil {
				return entry, err
			}
			if info.number != "" {
				asKey = info.number
				if info.name != "" {
					asKey += " (" + info.name + ")"
				}

				netKey += " (" + info.number + ")"
			}
		}

		if !countedNet[netKey] {
			countedNet[netKey] = true
			sc.tally(sc.byNet, &sc.netOrd, netKey, entry.Name)
		}
		if !countedAS[asKey] {
			countedAS[asKey] = true
			sc.tally(sc.byAS, &sc.asOrd, asKey, entry.Name)
		}
	}

	sort.Strings(entry.Addresses)
	return entry, nil
}

// blockOf returns the netblock that holds an address: one stored as
// containing it, or, when the database can search ranges, the most specific
// stored netblock whose range does. It returns an empty asset when none is
// found.
func (sc *subScan) blockOf(ip graph.Asset) (graph.Asset, error) {
	steps, err := sc.s.w.steps(ip)
	if err != nil {
		return graph.Asset{}, err
	}
	for _, st := range steps {
		if !st.forward && st.other.Type == "Netblock" {
			return st.other, nil
		}
	}

	return sc.s.w.netblockByRange(ip)
}

// autonomousSystem returns the number and name of the autonomous system a
// netblock belongs to, cached per run. The name comes from the autonomous
// system's registration record when one is stored.
func (sc *subScan) autonomousSystem(block graph.Asset) (asInfo, error) {
	if info, ok := sc.asOf[block.ID]; ok {
		return info, nil
	}

	steps, err := sc.s.w.steps(block)
	if err != nil {
		return asInfo{}, err
	}

	var as graph.Asset
	for _, st := range steps {
		if st.other.Type == "AutonomousSystem" {
			as = st.other
			break
		}
	}

	var info asInfo
	if as.ID != "" {
		info.number = "AS" + strings.TrimPrefix(strings.ToUpper(graph.AssetLabel(as)), "AS")
		info.name = sc.autonomousSystemName(as)
	}

	sc.asOf[block.ID] = info
	return info, nil
}

// autonomousSystemName reads the name on an autonomous system's stored
// registration record, or an empty string when none is stored.
func (sc *subScan) autonomousSystemName(as graph.Asset) string {
	steps, err := sc.s.w.steps(as)
	if err != nil {
		return ""
	}
	for _, st := range steps {
		if st.forward && st.other.Type == "AutnumRecord" {
			if name := graph.ContentString(st.other, "name"); name != "" {
				return name
			}
		}
	}

	return ""
}

// tally counts name under key, keeping a few example names and the order
// keys were first seen.
func (sc *subScan) tally(groups map[string]*ChangeGroup, order *[]string, key, name string) {
	g, ok := groups[key]
	if !ok {
		g = &ChangeGroup{Key: key}
		groups[key] = g
		*order = append(*order, key)
	}

	g.Count++
	if len(g.Examples) < subdomainsExamples {
		graph.AddUnique(&g.Examples, name)
	}
}

// groups returns the tallied groups, most names first and then by key so
// the order is stable.
func (sc *subScan) groups(m map[string]*ChangeGroup, order []string) []ChangeGroup {
	out := make([]ChangeGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *m[k])
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}

		return out[i].Key < out[j].Key
	})
	return out
}

// Text implements Report.
func (r SubdomainsReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Subdomains of %s: %d name(s), %d with DNS records, %d resolving to an address, "+
		"%d discovered without records (%d reads).\n", subject, len(r.Names), r.WithRecords, r.Resolving,
		r.DiscoveredOnly, r.Reads)

	if len(r.Names) == 0 {
		b.WriteString("\nNo controlled name is stored.\n")
		return b.String()
	}

	b.WriteString("\n")
	for _, n := range r.Names {
		if len(n.Records) == 0 {
			fmt.Fprintf(&b, "  %s (discovered, no DNS records)\n", n.Name)
			continue
		}

		line := n.Name + " [" + strings.Join(n.Records, ", ") + "]"
		if len(n.Aliases) > 0 {
			line += " -> " + strings.Join(n.Aliases, " -> ")
		}
		if len(n.Addresses) > 0 {
			line += " -> " + strings.Join(n.Addresses, ", ")
		}

		fmt.Fprintf(&b, "  %s\n", line)
	}

	if len(r.ByAutonomousSystem) > 0 {
		b.WriteString("\nNames by autonomous system:\n")
		for _, g := range r.ByAutonomousSystem {
			fmt.Fprintf(&b, "  %s: %d name(s), e.g. %s\n", g.Key, g.Count, strings.Join(g.Examples, ", "))
		}
	}
	if len(r.ByNetblock) > 0 {
		b.WriteString("\nNames by netblock:\n")
		for _, g := range r.ByNetblock {
			fmt.Fprintf(&b, "  %s: %d name(s), e.g. %s\n", g.Key, g.Count, strings.Join(g.Examples, ", "))
		}
	}

	b.WriteString("\nThese are stored names and resolutions, not a live scan." + r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r SubdomainsReport) Facts() []string {
	out := make([]string, 0, len(r.Names)+len(r.ByAutonomousSystem))
	for _, n := range r.Names {
		out = append(out, "controls name "+n.Name)
	}
	for _, g := range r.ByAutonomousSystem {
		out = append(out, fmt.Sprintf("%d name(s) in %s", g.Count, g.Key))
	}

	return out
}
