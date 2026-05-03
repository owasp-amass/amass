// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/biter777/countries"
	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

var createOrgLock sync.Mutex

func CreateOrgAsset(sess et.Session, obj *dbt.Entity, rel oam.Relation, o *oamorg.Organization, src *et.Source) (*dbt.Entity, error) {
	createOrgLock.Lock()
	defer createOrgLock.Unlock()

	if o == nil || o.Name == "" {
		return nil, errors.New("missing the organization name")
	} else if src == nil {
		return nil, errors.New("missing the source")
	}

	orgent, err := FindOrgByNameClaim(sess, o.Name, src)
	if err != nil && o.LegalName != "" {
		orgent, _ = FindOrgByLegalNameClaim(sess, o.LegalName, src)
	}

	normName := genNormName(o)
	if o.Jurisdiction != "" {
		// attempt to normalize the jurisdiction country
		if code := countries.ByName(o.Jurisdiction); code.IsValid() {
			o.Jurisdiction = code.Alpha2()
		}
		if o.RegistrationID != "" {
			orgent, _ = FindOrgByJurisdictionAndRegistrationIDClaim(sess, o.Jurisdiction, o.RegistrationID)
		}
		if orgent == nil {
			orgent, _ = FindOrgByNormNameAndJurisdictionClaim(sess, normName, o.Jurisdiction)
		}
	}

	dName := o.Name
	o.Name = normName
	if orgent == nil && obj != nil {
		orgent = dedupChecks(sess, obj, o)
	}

	if orgent == nil {
		ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
		defer cancel()

		var err error
		o.ID = genStableOrgID(o)
		orgent, err = sess.DB().CreateAsset(ctx, o)
		if err != nil || orgent == nil {
			return nil, errors.New("failed to create the Organization asset")
		}
	}

	if orgent != nil {
		// create name and jurisdiction claims provided by the caller
		_, _ = CreateOrgNameClaim(sess, orgent, dName, src)

		if o.LegalName != "" {
			_, _ = CreateOrgLegalNameClaim(sess, orgent, o.LegalName, src)
		}
		if o.Jurisdiction != "" {
			_ = CreateOrgJurisdictionClaim(sess, orgent, o.Jurisdiction)
		}
		if o.RegistrationID != "" {
			_, _ = CreateOrgRegistrationIDClaim(sess, orgent, o.RegistrationID, src)
		}

		ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
		defer cancel()

		// identify this caller as a source of the Organization asset
		_, _ = sess.DB().CreateEntityProperty(ctx, orgent, &oamgen.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})

		if obj != nil && rel != nil && obj.ID != orgent.ID {
			ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
			defer cancel()

			if err := createRelation(ctx, sess, obj, rel, orgent, src); err != nil {
				return nil, err
			}
		}

		return orgent, nil
	}

	return nil, errors.New("failed to discover or create the Organization asset")
}

func genNormName(o *oamorg.Organization) string {
	name := o.Name

	if o.LegalName != "" {
		name = o.LegalName
	}

	return ExtractBrandName(strings.ToLower(name))
}

func genStableOrgID(o *oamorg.Organization) string {
	id := uuid.New().String()
	return fmt.Sprintf("%s:%s", o.Name, id)
}

func createRelation(ctx context.Context, sess et.Session, obj *dbt.Entity, rel oam.Relation, subject *dbt.Entity, src *et.Source) error {
	edge, err := sess.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: obj,
		ToEntity:   subject,
	})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}

	_, err = sess.DB().CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
	return err
}
