// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensNetwork asks for the network infrastructure of a domain or
// organization: the address space and autonomous systems it holds, where
// its names resolve, what is inside its own space, and what does not fit.
// The answer is built in Go; nothing is written.
const LensNetwork = "network"

// OwnNetwork is a netblock the subject holds.
type OwnNetwork struct {
	CIDR    string `json:"cidr"`
	ID      string `json:"id"`
	Version int    `json:"version"`
	// Names counts the subject's names resolving into the network,
	// Addresses the subject's addresses stored inside it and Services the
	// services stored on those addresses.
	Names     int      `json:"names"`
	Addresses int      `json:"addresses"`
	Services  int      `json:"services"`
	Announced []string `json:"announced_by,omitempty"`
}

// OwnAS is an autonomous system the subject holds.
type OwnAS struct {
	Number string `json:"number"`
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	// Announces are the prefixes the AS announces; Foreign those not among
	// the subject's netblocks, such as a customer's or a provider's space.
	Announces []string `json:"announces"`
	Foreign   []string `json:"foreign,omitempty"`
}

// ForeignNames are the names of another domain found on addresses in the
// subject's own netblocks: a tenant, a partner or something left behind.
type ForeignNames struct {
	Domain    string   `json:"domain"`
	Names     int      `json:"names"`
	Addresses []string `json:"addresses"`
	Examples  []string `json:"examples"`
}

// HostingShare is where some of the subject's names resolve.
type HostingShare struct {
	Party    string   `json:"party"`
	PartyID  string   `json:"party_id,omitempty"`
	Own      bool     `json:"own,omitempty"`
	Names    int      `json:"names"`
	Networks []string `json:"networks,omitempty"`
	Examples []string `json:"examples,omitempty"`
}

// NetworkReport is the result of the network infrastructure lens.
type NetworkReport struct {
	Root      graph.Asset    `json:"root"`
	Owners    []string       `json:"owners,omitempty"`
	Footprint int            `json:"footprint"`
	Networks  []OwnNetwork   `json:"networks"`
	ASNs      []OwnAS        `json:"asns"`
	Hosting   []HostingShare `json:"hosting"`
	// Resolved counts the subject's names with a stored address or an
	// alias (CNAME) to another name, Aliased those reached through an
	// alias, and Unresolved those with neither.
	Resolved   int `json:"resolved"`
	Aliased    int `json:"aliased"`
	Unresolved int `json:"unresolved"`
	// Unused are the subject's netblocks no name of the subject resolves
	// into.
	Unused []string `json:"unused,omitempty"`
	// Foreign are other domains' names on addresses in the subject's
	// netblocks, by an address record or a pointer record.
	Foreign   []ForeignNames `json:"foreign,omitempty"`
	Reads     int            `json:"reads"`
	Truncated bool           `json:"truncated"`
	Reason    string         `json:"reason,omitempty"`
}

// netHostingExamples bounds the example names per hosting party.
const netHostingExamples = 3

// FindNetworkInfrastructure walks the controlled footprint of a domain or
// organization, as the vendors lens does, and reports the netblocks and
// autonomous systems it holds, where its names resolve (its own space or a
// provider's), what is stored inside its own space, and its netblocks no
// name uses. It reads only.
func FindNetworkInfrastructure(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (NetworkReport, error) {
	out := NetworkReport{Root: root}
	meaning := graph.MeaningsOf(schema)
	if schema == nil || meaning == nil {
		return out, errors.New("the network lens requires relationship semantics")
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
	w.maxAssets, w.maxReads = limits.assets(), limits.reads()
	roots := []graph.Asset{root}
	owners, err := w.owningOrganizations(root)
	if err != nil {
		return out, err
	}
	for _, o := range owners {
		out.Owners = append(out.Owners, graph.AssetLabel(o))
		roots = append(roots, o)
	}

	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return out, err
	}
	out.Footprint = len(owned)

	n := networkScan{w: w, owned: owned, nets: map[string]*OwnNetwork{}, hosting: map[string]*HostingShare{},
		blockNames: map[string]map[string]bool{}}
	n.d = dependencyScan{w: w, owned: owned, ownDomains: map[string]bool{}}
	for _, id := range order {
		a := owned[id]
		switch a.Type {
		case "Netblock":
			n.addNetwork(a)
		case "FQDN":
			n.d.ownDomains[graph.RegisteredDomain(graph.FQDNName(a))] = true
		}
	}
	for _, net := range n.nets {
		if p, err := netip.ParsePrefix(net.CIDR); err == nil {
			n.d.ownNets = append(n.d.ownNets, p.Masked())
		}
	}

	// The subject's own names and systems come first; the contents of its
	// netblocks, which can be large, take what the read budget leaves.
	for pass := 0; pass < 2; pass++ {
		for _, id := range order {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if report.Reads >= w.maxReads {
				w.truncate("database read limit")
				break
			}

			a := owned[id]
			var err error
			switch {
			case pass == 0 && a.Type == "FQDN":
				err = n.resolve(a, &out)
			case pass == 0 && a.Type == "IPAddress":
				err = n.inside(a)
			case pass == 0 && a.Type == "AutonomousSystem":
				err = n.autonomousSystem(a, &out)
			case pass == 1 && a.Type == "Netblock":
				err = n.contents(a)
			}
			if err != nil {
				return out, err
			}
		}
	}

	for _, net := range n.nets {
		net.Names = len(n.blockNames[net.ID])
		if net.Names == 0 {
			out.Unused = append(out.Unused, net.CIDR)
		}
		out.Networks = append(out.Networks, *net)
	}
	sort.Slice(out.Networks, func(i, j int) bool {
		a, b := out.Networks[i], out.Networks[j]
		if a.Names != b.Names {
			return a.Names > b.Names
		}
		return a.CIDR < b.CIDR
	})
	sort.Strings(out.Unused)
	for _, f := range n.foreign {
		sort.Strings(f.Addresses)
		out.Foreign = append(out.Foreign, *f)
	}
	sort.Slice(out.Foreign, func(i, j int) bool {
		a, b := out.Foreign[i], out.Foreign[j]
		if a.Names != b.Names {
			return a.Names > b.Names
		}
		return a.Domain < b.Domain
	})
	for _, h := range n.hosting {
		sort.Strings(h.Networks)
		out.Hosting = append(out.Hosting, *h)
	}
	sort.Slice(out.Hosting, func(i, j int) bool {
		a, b := out.Hosting[i], out.Hosting[j]
		if a.Names != b.Names {
			return a.Names > b.Names
		}
		return a.Party < b.Party
	})
	sort.Slice(out.ASNs, func(i, j int) bool { return out.ASNs[i].Number < out.ASNs[j].Number })

	out.Reads = report.Reads
	out.Truncated, out.Reason = report.Truncated, report.Reason
	return out, nil
}

type networkScan struct {
	w     *lensWalker
	d     dependencyScan
	owned map[string]graph.Asset
	nets  map[string]*OwnNetwork
	// prefixes are the parsed CIDRs of nets, by netblock ID.
	prefixes map[string]netip.Prefix
	// blockNames are the subject's names resolving into each own netblock.
	blockNames map[string]map[string]bool
	hosting    map[string]*HostingShare
	// blockParty caches the party holding a netblock outside the footprint.
	blockParty map[string]*HostingShare
	// hosted marks each party and name counted in hosting.
	hosted map[string]bool
	// counted marks the addresses counted in a netblock.
	counted map[string]bool
	// foreign collects other domains' names on the subject's addresses.
	foreign     map[string]*ForeignNames
	foreignSeen map[string]bool
}

func (n *networkScan) addNetwork(a graph.Asset) {
	cidr := graph.ContentString(a, "cidr")
	version := 4
	if p, err := netip.ParsePrefix(cidr); err == nil && p.Addr().Is6() {
		version = 6
	}
	n.nets[a.ID] = &OwnNetwork{CIDR: cidr, ID: a.ID, Version: version}
	if p, err := netip.ParsePrefix(cidr); err == nil {
		if n.prefixes == nil {
			n.prefixes = map[string]netip.Prefix{}
		}
		n.prefixes[a.ID] = p.Masked()
	}
}

// ownNetwork returns the subject's netblock an address is in: the netblock
// stored for it, or else the most specific of the subject's netblocks whose
// range holds it, since an address is not always linked to its netblock.
func (n *networkScan) ownNetwork(ip, block graph.Asset) *OwnNetwork {
	if net, ok := n.nets[block.ID]; ok && block.ID != "" {
		return net
	}
	addr, err := netip.ParseAddr(graph.ContentString(ip, "address"))
	if err != nil {
		return nil
	}

	var best *OwnNetwork
	bits := -1
	for id, p := range n.prefixes {
		if p.Contains(addr) && p.Bits() > bits {
			best, bits = n.nets[id], p.Bits()
		}
	}
	return best
}

// resolve records where a name is hosted. It follows the name's alias
// (CNAME) chain to the addresses stored for it; each is in one of the
// subject's netblocks or the network of the party holding it. An alias to
// a name with no stored address is hosted by whoever controls the target.
func (n *networkScan) resolve(name graph.Asset, out *NetworkReport) error {
	res, err := resolveName(n.w, name)
	if err != nil {
		return err
	}

	switch {
	case len(res.Addresses) > 0:
		out.Resolved++
	case res.Aliased():
		out.Resolved++
		target := res.Target(name)
		party, id, own, _, err := n.d.party(target)
		if err != nil {
			return err
		}
		if own {
			party = "own"
		} else if party == "" {
			party = vendorNameOf(graph.RegisteredDomain(graph.FQDNName(target)))
		}
		n.share(party, id, own, "", name)
	default:
		out.Unresolved++
	}
	if res.Aliased() {
		out.Aliased++
	}

	for _, addr := range res.Addresses {
		block, err := n.blockOf(addr)
		if err != nil {
			return err
		}
		if net := n.ownNetwork(addr, block); net != nil {
			if n.blockNames[net.ID] == nil {
				n.blockNames[net.ID] = map[string]bool{}
			}
			n.blockNames[net.ID][name.ID] = true
			n.share("own", "", true, net.CIDR, name)
			continue
		}

		party, id, own, err := n.party(block, addr)
		if err != nil {
			return err
		}
		n.share(party, id, own, graph.ContentString(block, "cidr"), name)
	}
	return nil
}

// blockOf returns the netblock a stored address is in, or an empty asset.
func (n *networkScan) blockOf(ip graph.Asset) (graph.Asset, error) {
	steps, err := n.w.steps(ip)
	if err != nil {
		return graph.Asset{}, err
	}
	for _, s := range steps {
		if !s.forward && s.other.Type == "Netblock" {
			return s.other, nil
		}
	}

	return graph.Asset{}, nil
}

// party names who holds a netblock outside the footprint, or the address
// itself when no netblock is stored for it.
func (n *networkScan) party(block, ip graph.Asset) (string, string, bool, error) {
	target := block
	if target.ID == "" {
		target = ip
	}
	if n.blockParty == nil {
		n.blockParty = map[string]*HostingShare{}
	}
	if h, ok := n.blockParty[target.ID]; ok {
		return h.Party, h.PartyID, h.Own, nil
	}

	name, id, own, _, err := n.d.party(target)
	if err != nil {
		return "", "", false, err
	}
	if name == "" && !own {
		name = UnattributedAddresses
	}
	if own {
		name = "own"
	}
	n.blockParty[target.ID] = &HostingShare{Party: name, PartyID: id, Own: own}
	return name, id, own, nil
}

// share counts name as hosted by party, once however many of its
// addresses the party holds.
func (n *networkScan) share(party, id string, own bool, cidr string, name graph.Asset) {
	h, ok := n.hosting[party]
	if !ok {
		h = &HostingShare{Party: party, PartyID: id, Own: own}
		n.hosting[party] = h
	}
	if cidr != "" {
		graph.AddUnique(&h.Networks, cidr)
	}
	if n.hosted == nil {
		n.hosted = map[string]bool{}
	}
	if key := party + "\x00" + name.ID; !n.hosted[key] {
		n.hosted[key] = true
		h.Names++
		if len(h.Examples) < netHostingExamples {
			graph.AddUnique(&h.Examples, graph.FQDNName(name))
		}
	}
}

// contents counts the addresses stored inside one of the subject's
// netblocks, whoever's names they carry.
func (n *networkScan) contents(block graph.Asset) error {
	net, ok := n.nets[block.ID]
	if !ok {
		return nil
	}
	steps, err := n.w.steps(block)
	if err != nil {
		return err
	}

	dns := loadDNSRules()
	for _, s := range steps {
		if s.forward && slices.Contains(dns.AddressTypes, s.other.Type) {
			if err := n.address(s.other, net); err != nil {
				return err
			}
		}
	}

	return nil
}

// inside counts an address of the footprint in one of the subject's
// netblocks, when the netblock does not list it.
func (n *networkScan) inside(ip graph.Asset) error {
	if n.counted[ip.ID] {
		return nil
	}
	steps, err := n.w.steps(ip)
	if err != nil {
		return err
	}

	var block graph.Asset
	for _, s := range steps {
		if !s.forward && s.other.Type == "Netblock" {
			block = s.other
		}
	}
	if net := n.ownNetwork(ip, block); net != nil {
		return n.address(ip, net)
	}

	return nil
}

// address counts an address in net, the services stored on it and the
// names of other domains it carries.
func (n *networkScan) address(ip graph.Asset, net *OwnNetwork) error {
	if n.counted == nil {
		n.counted = map[string]bool{}
	}
	if n.counted[ip.ID] {
		return nil
	}
	n.counted[ip.ID] = true

	steps, err := n.w.steps(ip)
	if err != nil {
		return err
	}

	dns := loadDNSRules()
	net.Addresses++
	for _, s := range steps {
		switch {
		case s.forward && s.other.Type == "Service":
			net.Services++
		case s.purpose == dns.DNSPurpose && s.other.Type == "FQDN":
			// An address record names it from the name's side; a pointer
			// record from the address's side.
			n.foreignName(ip, s.other)
		}
	}

	return nil
}

// foreignName records name when it belongs to another domain than the
// subject's.
func (n *networkScan) foreignName(ip, name graph.Asset) {
	host := graph.FQDNName(name)
	domain := graph.RegisteredDomain(host)
	if domain == "" || n.d.ownDomains[domain] || reverseZone(domain) || reservedName(host) {
		return
	}
	if _, mine := n.owned[name.ID]; mine {
		return
	}
	if n.foreign == nil {
		n.foreign, n.foreignSeen = map[string]*ForeignNames{}, map[string]bool{}
	}
	f, ok := n.foreign[domain]
	if !ok {
		f = &ForeignNames{Domain: domain}
		n.foreign[domain] = f
	}
	if len(f.Addresses) < netHostingExamples {
		graph.AddUnique(&f.Addresses, graph.ContentString(ip, "address"))
	}
	if !n.foreignSeen[name.ID] {
		n.foreignSeen[name.ID] = true
		f.Names++
		if len(f.Examples) < netHostingExamples {
			graph.AddUnique(&f.Examples, host)
		}
	}
}

// autonomousSystem records an AS the subject holds and the prefixes it
// announces.
func (n *networkScan) autonomousSystem(as graph.Asset, out *NetworkReport) error {
	steps, err := n.w.steps(as)
	if err != nil {
		return err
	}

	o := OwnAS{Number: "AS" + strings.TrimPrefix(strings.ToUpper(graph.AssetLabel(as)), "AS"), ID: as.ID}
	for _, s := range steps {
		if !s.forward {
			continue
		}
		switch {
		case s.other.Type == "Netblock":
			cidr := graph.ContentString(s.other, "cidr")
			graph.AddUnique(&o.Announces, cidr)
			if net, ok := n.nets[s.other.ID]; ok {
				graph.AddUnique(&net.Announced, o.Number)
			} else {
				graph.AddUnique(&o.Foreign, cidr)
			}
		case s.attr == semantics.SameSubject && o.Name == "":
			o.Name = graph.ContentString(s.other, "name")
		}
	}
	sort.Strings(o.Announces)
	sort.Strings(o.Foreign)
	out.ASNs = append(out.ASNs, o)
	return nil
}

// FormatNetworkReport renders the network infrastructure lens for a
// terminal.
func FormatNetworkReport(r NetworkReport) string {
	var b strings.Builder
	scope := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		scope += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Network infrastructure of %s, from %d controlled asset(s) (%d reads).\n", scope, r.Footprint,
		r.Reads)

	v4, v6 := 0, 0
	for _, n := range r.Networks {
		if n.Version == 6 {
			v6++
		} else {
			v4++
		}
	}
	if len(r.Networks) == 0 && len(r.ASNs) == 0 {
		b.WriteString("No netblock or autonomous system registered to it is stored.\n")
	} else {
		fmt.Fprintf(&b, "\nIts own address space: %d IPv4 and %d IPv6 netblock(s)", v4, v6)
		if len(r.ASNs) > 0 {
			fmt.Fprintf(&b, ", %d autonomous system(s)", len(r.ASNs))
		}
		b.WriteString(".\n")
		for _, n := range r.Networks {
			fmt.Fprintf(&b, "  %s: %d of its names resolve here, %d address(es) stored, %d service(s)", n.CIDR,
				n.Names, n.Addresses, n.Services)
			if len(n.Announced) > 0 {
				fmt.Fprintf(&b, ", announced by %s", strings.Join(n.Announced, ", "))
			}
			b.WriteString("\n")
		}
		for _, a := range r.ASNs {
			fmt.Fprintf(&b, "  %s", a.Number)
			if a.Name != "" {
				fmt.Fprintf(&b, " (%s)", a.Name)
			}
			fmt.Fprintf(&b, " announces %d prefix(es)", len(a.Announces))
			if len(a.Foreign) > 0 {
				fmt.Fprintf(&b, ", %d of them not its own: %s", len(a.Foreign), strings.Join(a.Foreign, ", "))
			}
			b.WriteString("\n")
		}
	}

	if total := r.Resolved; total > 0 {
		fmt.Fprintf(&b, "\nWhere its %d resolving name(s) are hosted", total)
		if r.Aliased > 0 {
			fmt.Fprintf(&b, " (%d through an alias)", r.Aliased)
		}
		b.WriteString(":\n")
		for _, h := range r.Hosting {
			party := h.Party
			if h.Own {
				party = "its own networks"
			}
			fmt.Fprintf(&b, "  %s: %d (%.0f%%)", party, h.Names, 100*float64(h.Names)/float64(total))
			if len(h.Examples) > 0 {
				fmt.Fprintf(&b, ", e.g. %s", strings.Join(h.Examples, ", "))
			}
			b.WriteString("\n")
		}
	}
	if r.Unresolved > 0 {
		fmt.Fprintf(&b, "Names with no stored address: %d.\n", r.Unresolved)
	}

	if len(r.Unused) > 0 {
		fmt.Fprintf(&b, "\nNetblocks registered to it that none of its names use (%d): %s\n", len(r.Unused),
			strings.Join(r.Unused, ", "))
	}

	if len(r.Foreign) > 0 {
		fmt.Fprintf(&b, "\nNames of %d other domain(s) on addresses in its netblocks (tenants, partners or "+
			"leftovers):\n", len(r.Foreign))
		for _, f := range r.Foreign {
			fmt.Fprintf(&b, "  %s: %d name(s) on %s, e.g. %s\n", f.Domain, f.Names, strings.Join(f.Addresses, ", "),
				strings.Join(f.Examples, ", "))
		}
	}

	b.WriteString("These are stored registrations and resolutions, not a live scan.")
	if r.Truncated {
		fmt.Fprintf(&b, " Results are partial (%s); raise -max-assets or -max-reads to cover more.", r.Reason)
	}
	b.WriteString("\n")
	return b.String()
}
