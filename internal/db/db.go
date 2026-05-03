// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

func FindByFQDNScope(ctx context.Context, db repository.Repository, entity *dbt.Entity, since time.Time) ([]*dbt.Entity, error) {
	fqdn, valid := entity.Asset.(*oamdns.FQDN)
	if !valid {
		return nil, errors.New("input entity must be of asset type FQDN")
	}

	set := stringset.New(entity.Asset.Key())
	defer set.Close()

	results := []*dbt.Entity{entity}
	if edges, err := db.OutgoingEdges(ctx, entity, since, "node"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if to, err := db.FindEntityById(ctx, edge.ToEntity.ID); err == nil && to != nil && !set.Has(to.Asset.Key()) {
				if tofqdn, valid := to.Asset.(*oamdns.FQDN); !valid || !strings.HasSuffix(tofqdn.Name, "."+fqdn.Name) {
					continue
				}

				set.Insert(to.Asset.Key())
				if findings, err := FindByFQDNScope(ctx, db, to, since); err == nil && len(findings) > 0 {
					results = append(results, findings...)
				}
			}
		}
	}
	return results, nil
}
