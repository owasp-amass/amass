// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"net/netip"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// sharedAddress reports whether an address or netblock is shared
// infrastructure: a private or other reserved address, or a range a cloud or
// CDN provider publishes as its own (a provider edge on it or on the netblock
// holding it). Unrelated parties depend on such infrastructure, so it gives
// no hosting or fingerprint signal.
func (g *gapSearch) sharedAddress(a graph.Asset) (bool, error) {
	if a.Type != "IPAddress" && a.Type != "Netblock" {
		return false, nil
	}
	if v, ok := g.shared[a.ID]; ok {
		return v, nil
	}

	shared, err := g.providerRange(a)
	if err != nil {
		return false, err
	}
	if g.shared == nil {
		g.shared = map[string]bool{}
	}
	g.shared[a.ID] = shared
	return shared, nil
}

func (g *gapSearch) providerRange(a graph.Asset) (bool, error) {
	if a.Type == "IPAddress" {
		addr, err := netip.ParseAddr(graph.ContentString(a, "address"))
		if err != nil {
			return false, nil
		}
		if reservedAddress(addr) {
			return true, nil
		}

		block, err := g.netblockOf(a)
		if err != nil || block.ID == "" {
			return false, err
		}
		a = block
	}

	_, _, _, ok, err := dependencyScan{w: g.w}.cloudProvider([]graph.Asset{a})
	return ok, err
}

// netblockOf returns the netblock holding an address: the one a stored
// contains relation names, else the most specific stored range holding it.
func (g *gapSearch) netblockOf(ip graph.Asset) (graph.Asset, error) {
	steps, err := g.w.steps(ip)
	if err != nil {
		return graph.Asset{}, err
	}
	for _, s := range steps {
		if !s.forward && s.edge.Label == "contains" && s.other.Type == "Netblock" {
			return s.other, nil
		}
	}

	return g.w.netblockByRange(ip)
}

// reservedAddress reports whether an address is private, shared (RFC 6598)
// or otherwise not a global unicast address on the Internet.
func reservedAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	return !addr.IsGlobalUnicast() || addr.IsPrivate() || cgnatRange.Contains(addr)
}

// cgnatRange is the shared address space for carrier-grade NAT (RFC 6598).
var cgnatRange = netip.MustParsePrefix("100.64.0.0/10")

// servedFromSharedInfrastructure reports whether a name or address is served
// only from shared infrastructure: an address that is (sharedAddress), or a
// name all of whose stored addresses are.
func (g *gapSearch) servedFromSharedInfrastructure(a graph.Asset) (bool, error) {
	switch a.Type {
	case "IPAddress":
		return g.sharedAddress(a)
	case "FQDN":
	default:
		return false, nil
	}

	steps, err := g.w.steps(a)
	if err != nil {
		return false, err
	}

	var addrs int
	for _, s := range steps {
		if !s.forward || s.edge.Label != "dns_record" || s.other.Type != "IPAddress" {
			continue
		}

		addrs++
		if shared, err := g.sharedAddress(s.other); err != nil || !shared {
			return false, err
		}
	}
	return addrs > 0, nil
}

// providerManagedCertificate reports whether a certificate covers a name that
// marks it as one a CDN or hosting provider manages for many customers
// (ProviderManagedName).
func (g *gapSearch) providerManagedCertificate(cert graph.Asset) (bool, error) {
	if ProviderManagedName(graph.ContentString(cert, "subject_common_name")) {
		return true, nil
	}

	steps, err := g.w.steps(cert)
	if err != nil {
		return false, err
	}
	for _, s := range steps {
		if s.forward && s.other.Type == "FQDN" && ProviderManagedName(graph.AssetLabel(s.other)) {
			return true, nil
		}
	}
	return false, nil
}
