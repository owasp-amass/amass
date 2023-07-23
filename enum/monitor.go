// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"net/netip"
	"strings"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
)

const falsePositiveThreshold int = 100

func (e *Enumeration) checkForMissedWildcards(addr string) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return
	}

	var t string
	if ip.Is4() {
		t = "IPv4"
	} else if ip.Is6() {
		t = "IPv6"
	} else {
		return
	}

	results, err := e.graph.DB.FindByContent(&network.IPAddress{
		Address: ip,
		Type:    t,
	}, e.Config.CollectionStartTime.UTC())
	if err != nil {
		return
	}

	var asset *types.Asset
	for _, res := range results {
		if i, ok := res.Asset.(network.IPAddress); ok && i.Address.String() == addr {
			asset = res
			break
		}
	}
	if asset == nil {
		return
	}

	in, err := e.graph.DB.IncomingRelations(asset, e.Config.CollectionStartTime.UTC(), "a_record", "aaaa_record")
	if err != nil {
		return
	}

	if len(in) < falsePositiveThreshold {
		return
	}

	subsToAssets := make(map[string][]string)
	for _, rel := range in {
		n, err := e.graph.DB.FindById(rel.FromAsset.ID, e.Config.CollectionStartTime.UTC())
		if err != nil {
			continue
		} else if fqdn, ok := n.Asset.(domain.FQDN); ok {
			parts := strings.Split(fqdn.Name, ".")
			sub := strings.Join(parts[1:], ".")
			subsToAssets[sub] = append(subsToAssets[sub], rel.FromAsset.ID)
		}
	}

	for sub, assets := range subsToAssets {
		if len(assets) < falsePositiveThreshold {
			continue
		}

		e.Config.BlacklistSubdomain(sub)
		for _, id := range assets {
			_ = e.graph.DB.DeleteAsset(id)
		}
	}
}
