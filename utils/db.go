// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
)

func FindByFQDNScope(db repository.Repository, entity *dbt.Entity, since time.Time) ([]*dbt.Entity, error) {
	set := stringset.New(entity.Asset.Key())
	defer set.Close()

	results := []*dbt.Entity{entity}
	if edges, err := db.OutgoingEdges(entity, since, "node"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if to, err := db.FindEntityById(edge.ToEntity.ID); err == nil && to != nil && !set.Has(to.Asset.Key()) {
				set.Insert(to.Asset.Key())

				if findings, err := FindByFQDNScope(db, to, since); err == nil && len(findings) > 0 {
					results = append(results, findings...)
				}
			}
		}
	}
	return results, nil
}
