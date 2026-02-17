// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func CreateOrgRDAPHandle(sess et.Session, orgent *dbt.Entity, handle string, src *et.Source) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	id := &oamgen.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", oamgen.ARINHandle, handle),
		ID:       handle,
		Type:     oamgen.ARINHandle,
	}

	ident, err := sess.DB().CreateAsset(ctx, id)
	if err != nil || ident == nil {
		return nil, err
	}

	_, err = sess.DB().CreateEntityProperty(ctx, ident, &oamgen.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
	if err != nil {
		return nil, err
	}

	if err := createRelation(ctx, sess, orgent, &oamgen.SimpleRelation{Name: "id"}, ident, src); err != nil {
		return nil, err
	}

	return ident, nil
}

func FindOrgByRDAPHandle(sess et.Session, handle string, src *et.Source) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	ids, err := sess.DB().FindEntitiesByContent(ctx, oam.Identifier, time.Time{}, 1, dbt.ContentFilters{
		"id":      handle,
		"id_type": oamgen.ARINHandle,
	})
	if err != nil || len(ids) != 1 {
		return nil, fmt.Errorf("failed to obtain the entity for Identifier - %s:%s", oamgen.ARINHandle, handle)
	}
	ident := ids[0]

	if edges, err := sess.DB().IncomingEdges(ctx, ident, time.Time{}, "id"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if tags, err := sess.DB().FindEdgeTags(ctx, edge, time.Time{}, src.Name); err != nil || len(tags) == 0 {
				continue
			}
			if o, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && o != nil {
				if _, valid := o.Asset.(*oamorg.Organization); valid {
					return o, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to obtain the Organization associated with Identifier - %s:%s", oamgen.ARINHandle, handle)
}
