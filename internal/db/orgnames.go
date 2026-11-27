// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// orgNamesPageSize is how many organizations are read per page.
const orgNamesPageSize = 500

// NormalizeOrganizationNames brings the stored name of every organization the
// engine created up to the current semantics.OrgNameKey, so lookups by name
// key find records stored under an earlier normalization. An organization
// the engine created is identified by its ID, "<name>:<UUID>" with the name
// it was stored under; organizations stored as given (an enumeration's seed
// organizations, curated records) are left as they are. A repository that
// cannot page or replace assets is left as it is. It returns how many names
// it rewrote.
func NormalizeOrganizationNames(ctx context.Context, db repository.Repository) (int, error) {
	pager, ok := db.(repository.EntityPager)
	if !ok {
		return 0, nil
	}
	replacer, ok := db.(repository.AssetReplacer)
	if !ok {
		return 0, nil
	}

	var rewritten int
	var after *dbt.EntityCursor
	for {
		ents, next, err := pager.EntitiesPage(ctx, oam.Organization, time.Time{}, after, orgNamesPageSize)
		if err != nil {
			return rewritten, err
		}
		for _, e := range ents {
			o, ok := e.Asset.(*oamorg.Organization)
			if !ok || !engineCreated(o) {
				continue
			}
			key := semantics.OrgNameKey(o.Name)
			if key == "" || key == o.Name {
				continue
			}
			renamed := *o
			renamed.Name = key
			if _, err := replacer.ReplaceAsset(ctx, &renamed); err != nil {
				return rewritten, err
			}
			rewritten++
		}
		if next == nil {
			return rewritten, nil
		}
		after = next
	}
}

// engineCreated reports whether an organization's ID is the one the engine
// gives the records it creates: its stored name, a colon and a UUID.
func engineCreated(o *oamorg.Organization) bool {
	// the name may itself hold a colon; the UUID is always last
	i := strings.LastIndex(o.ID, ":")
	if i < 0 || o.ID[:i] != o.Name {
		return false
	}
	_, err := uuid.Parse(o.ID[i+1:])
	return err == nil
}
