// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"errors"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// dependencyScan finds the outside parties that controlled assets depend
// on. Every rule comes from the semantics table:
//   - a third_party edge marked as a vendor names a dependency directly;
//   - an infrastructure edge names a dependency on the asset it reaches,
//     whose own vendor third_party edges are dependencies too (a service's
//     provider and software);
//   - a shared edge into a controlled asset (a certificate listing a
//     controlled name) is not a dependency itself, but its vendor
//     third_party edges are (the certificate's issuer).
//
// The party behind a dependency is whoever controls it (see party).
type dependencyScan struct {
	w          *lensWalker
	owned      map[string]graph.Asset
	ownDomains map[string]bool
	// ownNets are the footprint's netblocks: an address in one is
	// controlled even when no stored relationship says so.
	ownNets []netip.Prefix
	vendors vendorSet
	// self names the subject in table cells it controls.
	self string
	// pending are the dependencies scan found, until resolve records them.
	pending *[]dependency
}

// dependency is a vendor dependency scan found: s.other is a vendor of cur,
// reached by a step from from (cur, or an intermediate asset reached
// through prefix).
type dependency struct {
	cur, from graph.Asset
	s         step
	via       string
	prefix    []graph.WitnessEdge
}

// dependencyBatch is how many found dependencies resolve searches for the
// controllers of together.
const dependencyBatch = 1000

func (d dependencyScan) scan(cur graph.Asset) error {
	steps, err := d.w.steps(cur)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if _, mine := d.owned[s.other.ID]; mine {
			continue
		}

		via := cur.Type + " " + s.edge.Label
		hop := []graph.WitnessEdge{WitnessOf(s.edge, cur, s.other)}
		switch {
		case s.attr == graph.AttrThirdParty && s.forward && s.vendor:
			d.depend(cur, cur, s, via, nil)
		case s.attr == graph.AttrInfrastructure && s.forward:
			d.depend(cur, cur, s, via, nil)
			if err := d.through(cur, s.other, via, hop); err != nil {
				return err
			}
		case s.attr == graph.AttrShared && !s.forward:
			if err := d.through(cur, s.other, s.other.Type, hop); err != nil {
				return err
			}
		}
	}

	return nil
}

// through records the vendor dependencies of an intermediate asset on
// behalf of the controlled asset cur.
func (d dependencyScan) through(cur, mid graph.Asset, via string, prefix []graph.WitnessEdge) error {
	steps, err := d.w.steps(mid)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if _, mine := d.owned[s.other.ID]; mine || s.attr != graph.AttrThirdParty || !s.forward || !s.vendor {
			continue
		}
		d.depend(cur, mid, s, via+" "+mid.Type+" "+s.edge.Label, prefix)
	}

	return nil
}

// depend queues a dependency of cur for resolve.
func (d dependencyScan) depend(cur, from graph.Asset, s step, via string, prefix []graph.WitnessEdge) {
	*d.pending = append(*d.pending, dependency{cur: cur, from: from, s: s, via: via, prefix: prefix})
}

// queued is how many dependencies wait for resolve.
func (d dependencyScan) queued() int {
	return len(*d.pending)
}

// resolve records the party controlling each queued dependency as a vendor,
// searching for the controllers of all of them together, so one step read
// serves a round of every search.
func (d dependencyScan) resolve() error {
	pending := *d.pending
	*d.pending = nil
	others := make([]graph.Asset, 0, len(pending))
	for _, p := range pending {
		others = append(others, p.s.other)
	}
	if err := d.w.resolveControllers(others, d.owned); err != nil {
		return err
	}

	for _, p := range pending {
		name, id, own, witness, err := d.party(p.s.other)
		if err != nil {
			return err
		}
		if own || name == "" {
			continue
		}

		chain := append(append(append([]graph.WitnessEdge(nil), p.prefix...), WitnessOf(p.s.edge, p.from, p.s.other)),
			witness...)
		d.vendors.add(name, id, dependencyKind(p.s.purpose, p.s.other.Type), p.via, p.cur, chain)
	}

	return nil
}

// party names whoever controls a: the closest Organization along
// ownerPass; otherwise the operator of a network carrying it (an incoming
// infrastructure edge with purpose network, such as an autonomous system
// announcing its netblock); otherwise the most registration-like asset
// reached. own is set when control leads back to the footprint.
func (d dependencyScan) party(a graph.Asset) (string, string, bool, []graph.WitnessEdge, error) {
	c, err := d.w.controllerOf(a, d.owned)
	if err != nil {
		return "", "", false, nil, err
	}
	if c.own {
		return "", "", true, c.witness(c.visited[len(c.visited)-1].ID, d.w.assets), nil
	}
	// A netblock a provider publishes as its own names that provider as the
	// operator, from the provider's authoritative range feed. This is the
	// cloud or CDN hosting the address, more precise than the block's
	// registrant (which may be any of the provider's legal entities), so it
	// is preferred over the registrant when stored.
	if org, from, s, ok, err := d.cloudProvider(c.visited); err != nil {
		return "", "", false, nil, err
	} else if ok {
		_, own := d.owned[org.ID]
		witness := append(c.witness(from.ID, d.w.assets), WitnessOf(s.edge, from, org))
		return graph.AssetLabel(org), org.ID, own, witness, nil
	}
	if org, ok := namedOrganization(c.orgs); ok {
		_, own := d.owned[org.ID]
		return graph.AssetLabel(org), org.ID, own, c.witness(org.ID, d.w.assets), nil
	}
	for _, v := range c.visited {
		steps, err := d.w.steps(v)
		if err != nil {
			return "", "", false, nil, err
		}
		for _, s := range steps {
			if s.forward || s.attr != graph.AttrInfrastructure || s.purpose != "network" {
				continue
			}
			if _, mine := d.owned[s.other.ID]; mine {
				return "", "", true, nil, nil
			}

			oc, err := d.w.controllerOf(s.other, d.owned)
			if err != nil || oc.own {
				return "", "", oc.own, nil, err
			}

			base := append(c.witness(v.ID, d.w.assets), WitnessOf(s.edge, v, s.other))
			if org, ok := namedOrganization(oc.orgs); ok {
				return graph.AssetLabel(org), org.ID, false, append(base, oc.witness(org.ID, d.w.assets)...), nil
			}

			name, id, own, best, err := d.fallbackName(oc.visited)
			return name, id, own, append(base, oc.witness(best, d.w.assets)...), err
		}
	}

	// An address stored with no netblock is the network's whose stored
	// range holds it, when the graph can search by range.
	if a.Type == "IPAddress" {
		block, err := d.w.netblockByRange(a)
		if err != nil {
			return "", "", false, nil, err
		}
		if block.ID != "" && block.ID != a.ID {
			if _, mine := d.owned[block.ID]; mine {
				return "", "", true, nil, nil
			}

			return d.party(block)
		}
	}

	name, id, own, best, err := d.fallbackName(c.visited)
	return name, id, own, c.witness(best, d.w.assets), err
}

// cloudProvider returns the cloud or CDN provider an address or netblock is
// published under, reached through a network-purpose provider edge into an
// Organization (the only infrastructure/network transition that targets an
// Organization), with the asset and step it was found on so the caller can
// witness it. It reads what a provider's own range feed recorded, not
// ownership.
func (d dependencyScan) cloudProvider(visited []graph.Asset) (graph.Asset, graph.Asset, step, bool, error) {
	for _, v := range visited {
		steps, err := d.w.steps(v)
		if err != nil {
			return graph.Asset{}, graph.Asset{}, step{}, false, err
		}
		for _, s := range steps {
			if s.forward && s.attr == graph.AttrInfrastructure && s.purpose == "network" &&
				s.other.Type == "Organization" {
				return s.other, v, s, true, nil
			}
		}
	}

	return graph.Asset{}, graph.Asset{}, step{}, false, nil
}

// netblockByRange returns the most specific stored netblock whose range
// holds an address, or an empty asset when none does or the graph cannot
// search by range. Each address is looked up once per lens run.
func (w *lensWalker) netblockByRange(ip graph.Asset) (graph.Asset, error) {
	if b, ok := w.rangeBlocks[ip.ID]; ok {
		return b, nil
	}

	rr, ok := w.graph.(graph.RangeReader)
	addr, err := netip.ParseAddr(graph.ContentString(ip, "address"))
	if !ok || err != nil {
		return graph.Asset{}, nil
	}
	if w.outOfReads() {
		w.truncate("database read limit")
		return graph.Asset{}, nil
	}

	w.report.Reads++
	blocks, err := rr.NetblocksContaining(w.ctx, addr, 1)
	if err != nil && !errors.Is(err, graph.ErrUnsupported) {
		return graph.Asset{}, err
	}

	var block graph.Asset
	if len(blocks) > 0 {
		block = blocks[0]
		w.assets[block.ID] = block
	}
	if w.rangeBlocks == nil {
		w.rangeBlocks = map[string]graph.Asset{}
	}

	w.rangeBlocks[ip.ID] = block
	return block, nil
}

// namedOrganization returns the closest organization whose name identifies
// someone. Organizations stored before a placeholder such as "domain admin"
// was refused are skipped, so the party is named by what lies behind them.
func namedOrganization(orgs []graph.Asset) (graph.Asset, bool) {
	for _, o := range orgs {
		if !semantics.IsPlaceholderOrganization(graph.AssetLabel(o)) {
			return o, true
		}
	}

	return graph.Asset{}, false
}

// fallbackName names a party with no documented Organization by the
// visited asset closest to one (a registration record before the address
// it registers). FQDNs are named by their registrable domain, and a domain
// of the footprint counts as controlled.
func (d dependencyScan) fallbackName(visited []graph.Asset) (string, string, bool, string, error) {
	// An organization reached here was skipped as a placeholder (legal
	// department, someorganization); it never names the party.
	visited = slices.DeleteFunc(slices.Clone(visited), func(a graph.Asset) bool {
		return a.Type == "Organization" && semantics.IsPlaceholderOrganization(graph.AssetLabel(a))
	})
	if len(visited) == 0 {
		return "", "", false, "", nil
	}

	// At an equal distance an asset the search reached names the party
	// better than the asset it started from (an AS's registration record
	// rather than the AS number), then the shorter label wins.
	start := visited[0]
	best := start
	for _, v := range visited[1:] {
		dv, okv := d.w.ownerDist[v.Type]
		db, okb := d.w.ownerDist[best.Type]
		if okv && (!okb || dv < db || (dv == db && (best.ID == start.ID ||
			len(graph.AssetLabel(v)) < len(graph.AssetLabel(best))))) {
			best = v
		}
	}
	switch best.Type {
	case "ContactRecord":
		// A contact with no organization is named by its email domain: one of
		// the subject's own domains makes it the subject's own contact (a
		// university's network engineer), any other names the outside party.
		domains, err := d.w.contactEmailDomains(best)
		if err != nil {
			return "", "", false, "", err
		}
		for _, dom := range domains {
			if d.ownDomains[dom] {
				return "", "", true, best.ID, nil
			}
		}
		if len(domains) > 0 {
			return vendorNameOf(domains[0]), "", false, best.ID, nil
		}
		// Nothing identifies the contact (a redacted WHOIS contact), so its
		// record's internal key would name the party: name it by the next
		// asset reached instead, such as the domain the contact is for. A
		// person never names a party.
		var rest []graph.Asset
		for _, v := range visited {
			if v.ID != best.ID && v.Type != "Person" {
				rest = append(rest, v)
			}
		}
		if len(rest) > 0 {
			return d.fallbackName(rest)
		}
		// Only the contact record's internal key would name it.
		return "", "", false, best.ID, nil
	case "DomainRecord":
		if name := graph.ContentString(best, "domain"); name != "" {
			domain := graph.RegisteredDomain(name)
			return vendorNameOf(domain), "", d.ownDomains[domain], best.ID, nil
		}
	case "FQDN":
		domain := graph.RegisteredDomain(graph.FQDNName(best))
		if reverseZone(domain) || reservedName(graph.FQDNName(best)) {
			// An address's pointer name says nothing about who operates it,
			// and a reserved name reaches no one.
			return "", "", false, best.ID, nil
		}

		return vendorNameOf(domain), "", d.ownDomains[domain], best.ID, nil
	case "URL":
		// A URL is named by its host's registrable domain, like an FQDN: a
		// link back to one of the subject's own sites is its own.
		if u, err := url.Parse(graph.AssetLabel(best)); err == nil && u.Hostname() != "" {
			host := strings.ToLower(u.Hostname())
			if _, err := netip.ParseAddr(host); err != nil {
				if reservedName(host) {
					return "", "", false, best.ID, nil
				}
				domain := graph.RegisteredDomain(host)
				return vendorNameOf(domain), "", d.ownDomains[domain], best.ID, nil
			}
		}
	case "AutonomousSystem":
		// An autonomous system with no stored registration or organization is
		// named by its number in the form people write it.
		if n := graph.AssetLabel(best); n != "" && !strings.HasPrefix(strings.ToUpper(n), "AS") {
			return "AS" + n, best.ID, false, best.ID, nil
		}
	case "IPAddress":
		addr, err := netip.ParseAddr(graph.AssetLabel(best))
		if err != nil {
			break
		}
		addr = addr.Unmap()
		if reservedAddress(addr) {
			// Private and reserved addresses name no outside party.
			return "", "", false, best.ID, nil
		}
		for _, p := range d.ownNets {
			if p.Contains(addr) {
				return "", "", true, best.ID, nil
			}
		}

		// No network or organization is stored for the address, so who
		// operates it is unknown; the addresses are reported together.
		return UnattributedAddresses, "", false, best.ID, nil
	}

	return graph.AssetLabel(best), best.ID, false, best.ID, nil
}

// contactEmailDomains returns the registered domains of a contact record's
// email identifiers (the Identifier assets reached by a forward "id" edge whose
// id_type is email), lower-cased, de-duplicated and sorted. It is the shared
// helper used by the dependency scan and the ownership-gap search.
func (w *lensWalker) contactEmailDomains(cr graph.Asset) ([]string, error) {
	steps, err := w.steps(cr)
	if err != nil {
		return nil, err
	}

	set := map[string]bool{}
	for _, s := range steps {
		if !s.forward || s.edge.Label != "id" || s.other.Type != "Identifier" ||
			!strings.EqualFold(graph.ContentString(s.other, "id_type"), "email") {
			continue
		}
		if _, dom, ok := strings.Cut(strings.ToLower(graph.ContentString(s.other, "id")), "@"); ok && dom != "" {
			if reg := graph.RegisteredDomain(dom); reg != "" {
				set[reg] = true
			}
		}
	}

	out := make([]string, 0, len(set))
	for dom := range set {
		out = append(out, dom)
	}
	sort.Strings(out)
	return out, nil
}
