// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

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
		n.share(party, id, own, "", "", "", name)
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
			n.share("own", "", true, net.CIDR, "", "", name)
			continue
		}
		if ip, err := netip.ParseAddr(graph.ContentString(addr, "address")); err == nil && reservedAddress(ip) {
			n.share(PrivateAddresses, "", false, graph.ContentString(block, "cidr"), "", "", name)
			continue
		}

		party, id, own, err := n.party(block, addr)
		if err != nil {
			return err
		}
		region, service := "", ""
		if !own && block.ID != "" {
			region, service = graph.CloudMeta(n.w.ctx, n.w.graph, block.ID)
		}
		n.share(party, id, own, graph.ContentString(block, "cidr"), region, service, name)
	}
	return nil
}

// blockOf returns the netblock a stored address is in, or an empty asset:
// the netblock linked to it, or else the most specific stored netblock whose
// range holds it, when the graph can search by range.
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

	return n.w.netblockByRange(ip)
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
func (n *networkScan) share(party, id string, own bool, cidr, region, service string, name graph.Asset) {
	h, ok := n.hosting[party]
	if !ok {
		h = &HostingShare{Party: party, PartyID: id, Own: own}
		n.hosting[party] = h
	}
	if cidr != "" {
		graph.AddUnique(&h.Networks, cidr)
	}
	if region != "" {
		graph.AddUnique(&h.Regions, region)
	}
	if service != "" {
		graph.AddUnique(&h.Services, service)
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

	return n.addressesInRange(block, net)
}

// netRangeAddresses bounds the stored addresses one range read of a
// netblock returns.
const netRangeAddresses = 1000

// addressesInRange counts the addresses stored inside one of the subject's
// netblocks that the netblock is not linked to, when the graph can search
// by range.
func (n *networkScan) addressesInRange(block graph.Asset, net *OwnNetwork) error {
	rr, ok := n.w.graph.(graph.RangeReader)
	prefix, known := n.prefixes[block.ID]
	if !ok || !known {
		return nil
	}
	if n.w.outOfReads() {
		n.w.truncate("database read limit")
		return nil
	}

	n.w.report.Reads++
	addrs, more, err := rr.AddressesInRange(n.w.ctx, prefix, netRangeAddresses)
	if errors.Is(err, graph.ErrUnsupported) {
		return nil
	}
	if err != nil {
		return err
	}

	for _, a := range addrs {
		if err := n.address(a, net); err != nil {
			return err
		}
	}
	if more {
		n.w.truncate(fmt.Sprintf("%s holds more than %d stored addresses", net.CIDR, netRangeAddresses))
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
