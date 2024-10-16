// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"time"

	"github.com/owasp-amass/open-asset-model/network"
)

func (g *Graph) ReadASPrefixes(ctx context.Context, asn int, since time.Time) []string {
	var prefixes []string

	assets, err := g.DB.FindByContent(&network.AutonomousSystem{Number: asn}, since)
	if err != nil || len(assets) == 0 {
		return prefixes
	}

	if rels, err := g.DB.OutgoingRelations(assets[0], since, "announces"); err == nil && len(rels) > 0 {
		for _, rel := range rels {
			if a, err := g.DB.FindById(rel.ToAsset.ID, since); err != nil {
				continue
			} else if netblock, ok := a.Asset.(*network.Netblock); ok {
				prefixes = append(prefixes, netblock.CIDR.String())
			}
		}
	}
	return prefixes
}
