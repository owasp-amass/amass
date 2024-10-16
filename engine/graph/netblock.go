// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/network"
)

// UpsertNetblock adds a netblock/CIDR to the graph.
func (g *Graph) UpsertNetblock(ctx context.Context, cidr string) (*types.Asset, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}

	var t string
	ip := prefix.Addr()
	if ip.Is4() {
		t = "IPv4"
	} else if ip.Is6() {
		t = "IPv6"
	} else {
		return nil, fmt.Errorf("%s is not a valid IPv4 or IPv6 IP address", ip.String())
	}

	return g.DB.Create(nil, "", &network.Netblock{
		CIDR: prefix,
		Type: t,
	})
}
