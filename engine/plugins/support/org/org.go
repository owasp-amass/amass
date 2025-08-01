// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

var createOrgLock sync.Mutex

func createOrgUnlock(delay bool) {
	go func(d bool) {
		if d {
			time.Sleep(2 * time.Second)
		}
		createOrgLock.Unlock()
	}(delay)
}

func CreateOrgAsset(session et.Session, obj *dbt.Entity, rel oam.Relation, o *org.Organization, src *et.Source) (*dbt.Entity, error) {
	createOrgLock.Lock()
	defer createOrgUnlock(rel == nil)

	if o == nil || o.Name == "" {
		return nil, errors.New("missing the organization name")
	} else if src == nil {
		return nil, errors.New("missing the source")
	}

	var orgent *dbt.Entity
	if obj != nil {
		orgent = dedupChecks(session, obj, o)
	}

	if orgent == nil {
		name := strings.ToLower(o.Name)
		id := &general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", general.OrganizationName, name),
			ID:       name,
			Type:     general.OrganizationName,
		}

		if ident, err := session.Cache().CreateAsset(id); err == nil && ident != nil {
			_, _ = session.Cache().CreateEntityProperty(ident, &general.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})

			o.ID = uuid.New().String()
			orgent, err = session.Cache().CreateAsset(o)
			if err != nil || orgent == nil {
				return nil, errors.New("failed to create the OAM Organization asset")
			}

			_, _ = session.Cache().CreateEntityProperty(orgent, &general.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})

			if err := createRelation(session, orgent, &general.SimpleRelation{Name: "id"}, ident, src); err != nil {
				return nil, err
			}
		}
	}

	if obj != nil && rel != nil && orgent != nil && obj.ID != orgent.ID {
		if err := createRelation(session, obj, rel, orgent, src); err != nil {
			return nil, err
		}
	}

	return orgent, nil
}

func createRelation(session et.Session, obj *dbt.Entity, rel oam.Relation, subject *dbt.Entity, src *et.Source) error {
	edge, err := session.Cache().CreateEdge(&dbt.Edge{
		Relation:   rel,
		FromEntity: obj,
		ToEntity:   subject,
	})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}

	_, err = session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
	return err
}
