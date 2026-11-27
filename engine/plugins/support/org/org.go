// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/biter777/countries"
	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func CreateOrgAsset(sess et.Session, obj *dbt.Entity, rel oam.Relation, o *oamorg.Organization, src *et.Source) (*dbt.Entity, error) {
	if o == nil || o.Name == "" {
		return nil, errors.New("missing the organization name")
	} else if src == nil {
		return nil, errors.New("missing the source")
	}
	// Redaction placeholders and template text name no one.
	if semantics.IsPlaceholderOrganization(o.Name) {
		return nil, fmt.Errorf("%q is a placeholder, not an organization name", o.Name)
	}
	if semantics.IsPlaceholderOrganization(o.LegalName) {
		o.LegalName = ""
	}

	// Serialize creation of organizations that share a normalized name on a
	// canonical key, so concurrent collectors — within this process, and
	// across sessions where the backend supports it — converge on one record
	// through the reuse lookups below instead of each minting a new one.
	var orgent *dbt.Entity
	var oerr error
	_ = sess.DB().WithCanonicalLock(sess.Ctx(), "organization:"+genNormName(o), func() error {
		orgent, oerr = createOrgAssetLocked(sess, obj, rel, o, src)
		return oerr
	})
	return orgent, oerr
}

func createOrgAssetLocked(sess et.Session, obj *dbt.Entity, rel oam.Relation, o *oamorg.Organization, src *et.Source) (*dbt.Entity, error) {
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
		support.AddSource(ctx, sess, orgent, src)

		if obj != nil && rel != nil && obj.ID != orgent.ID {
			ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
			defer cancel()

			if _, err := support.Relate(ctx, sess, obj, rel, orgent, src); err != nil {
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

	return semantics.OrgNameKey(name)
}

func genStableOrgID(o *oamorg.Organization) string {
	id := uuid.New().String()
	return fmt.Sprintf("%s:%s", o.Name, id)
}
