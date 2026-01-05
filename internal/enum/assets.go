// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"net"
	"net/netip"

	"github.com/owasp-amass/amass/v5/config"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// ipnet2Prefix converts a net.IPNet to a netip.Prefix.
func ipnet2Prefix(ipn net.IPNet) netip.Prefix {
	addr, _ := netip.AddrFromSlice(ipn.IP)
	cidr, _ := ipn.Mask.Size()
	return netip.PrefixFrom(addr, cidr)
}

// convertScopeToAssets converts all items in a Scope to a slice of oam.Asset.
func convertScopeToAssets(scope *config.Scope) []oam.Asset {
	const ipv4 = "IPv4"
	const ipv6 = "IPv6"
	var assets []oam.Asset

	// Convert Domains to assets.
	for _, d := range scope.Domains {
		assets = append(assets, oamdns.FQDN{Name: d})
	}

	var ipType string
	// Convert Addresses to assets.
	for _, ip := range scope.Addresses {
		// Convert net.IP to net.IPAddr.
		if addr, ok := netip.AddrFromSlice(ip); ok {
			// Determine the IP type based on the address characteristics.
			if addr.Is4In6() {
				addr = netip.AddrFrom4(addr.As4())
				ipType = ipv4
			} else if addr.Is6() {
				ipType = ipv6
			} else {
				ipType = ipv4
			}

			// Create an asset from the IP address and append it to the assets slice.
			asset := oamnet.IPAddress{Address: addr, Type: ipType}
			assets = append(assets, asset)
		}
	}

	// Convert CIDRs to assets.
	for _, cidr := range scope.CIDRs {
		prefix := ipnet2Prefix(*cidr) // Convert net.IPNet to netip.Prefix.

		// Determine the IP type based on the address characteristics.
		addr := prefix.Addr()
		if addr.Is4In6() {
			ipType = ipv4
		} else if addr.Is6() {
			ipType = ipv6
		} else {
			ipType = ipv4
		}

		// Create an asset from the CIDR and append it to the assets slice.
		asset := oamnet.Netblock{CIDR: prefix, Type: ipType}
		assets = append(assets, asset)
	}

	// Convert ASNs to assets.
	for _, asn := range scope.ASNs {
		asset := oamnet.AutonomousSystem{Number: asn}
		assets = append(assets, asset)
	}
	return assets
}
