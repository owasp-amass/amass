// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// returns Asset objects by converting the contests of config.Scope
func makeAssets(config *config.Config) []*et.Asset {
	assets := convertScopeToAssets(config.Scope)

	for i, asset := range assets {
		asset.Name = fmt.Sprintf("asset#%d", i+1)
	}
	return assets
}

// ipnet2Prefix converts a net.IPNet to a netip.Prefix.
func ipnet2Prefix(ipn net.IPNet) netip.Prefix {
	addr, _ := netip.AddrFromSlice(ipn.IP)
	cidr, _ := ipn.Mask.Size()
	return netip.PrefixFrom(addr, cidr)
}

// convertScopeToAssets converts all items in a Scope to a slice of *Asset.
func convertScopeToAssets(scope *config.Scope) []*et.Asset {
	const ipv4 = "IPv4"
	const ipv6 = "IPv6"
	var assets []*et.Asset

	// Convert Domains to assets.
	for _, d := range scope.Domains {
		fqdn := oamdns.FQDN{Name: d}
		data := et.AssetData{
			OAMAsset: fqdn,
			OAMType:  fqdn.AssetType(),
		}
		asset := &et.Asset{
			Data: data,
		}
		assets = append(assets, asset)
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
			data := et.AssetData{
				OAMAsset: asset,
				OAMType:  asset.AssetType(),
			}
			assets = append(assets, &et.Asset{Data: data})
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
		data := et.AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &et.Asset{Data: data})
	}

	// Convert ASNs to assets.
	for _, asn := range scope.ASNs {
		asset := oamnet.AutonomousSystem{Number: asn}
		data := et.AssetData{
			OAMAsset: asset,
			OAMType:  asset.AssetType(),
		}
		assets = append(assets, &et.Asset{Data: data})
	}
	return assets
}
