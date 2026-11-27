// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// maxSameNameOrgs bounds how many organizations sharing a normalized name a
// claim lookup will examine for a compatible jurisdiction. Same-name clusters
// are small in practice; the cap keeps the lookup bounded when a common name
// is shared by many records.
const maxSameNameOrgs = 50

// registrationIDType is the id_type of an organization's registration number
// Identifier, read together with its jurisdiction.
const registrationIDType = "registration_id"

// An identifier claim is an organization's Identifier (Organization --id-->
// Identifier) whose edge a source vouches for. The source-scoped lookups find
// the organization a source already recorded under the same value, so one
// source's records converge without trusting another source's.

// CreateOrgNameClaim records name as one of the organization's names, claimed
// by src.
func CreateOrgNameClaim(sess et.Session, orgent *dbt.Entity, name string, src *et.Source) (*dbt.Entity, error) {
	return createIDClaim(sess, orgent, oamgen.OrganizationName, name, src)
}

// FindOrgByNameClaim returns the organization src recorded under name.
func FindOrgByNameClaim(sess et.Session, name string, src *et.Source) (*dbt.Entity, error) {
	return findOrgByIDClaim(sess, oamgen.OrganizationName, name, src)
}

// CreateOrgLegalNameClaim records name as the organization's legal name,
// claimed by src.
func CreateOrgLegalNameClaim(sess et.Session, orgent *dbt.Entity, name string, src *et.Source) (*dbt.Entity, error) {
	return createIDClaim(sess, orgent, oamgen.LegalName, name, src)
}

// FindOrgByLegalNameClaim returns the organization src recorded under the
// legal name.
func FindOrgByLegalNameClaim(sess et.Session, name string, src *et.Source) (*dbt.Entity, error) {
	return findOrgByIDClaim(sess, oamgen.LegalName, name, src)
}

// CreateOrgLEICode records the organization's Legal Entity Identifier,
// claimed by src.
func CreateOrgLEICode(sess et.Session, orgent *dbt.Entity, lei string, src *et.Source) (*dbt.Entity, error) {
	return createIDClaim(sess, orgent, oamgen.LEICode, lei, src)
}

// FindOrgByLEICode returns the organization src recorded under the LEI.
func FindOrgByLEICode(sess et.Session, lei string, src *et.Source) (*dbt.Entity, error) {
	return findOrgByIDClaim(sess, oamgen.LEICode, lei, src)
}

// CreateOrgRDAPHandle records the organization's registry (RDAP) handle,
// claimed by src.
func CreateOrgRDAPHandle(sess et.Session, orgent *dbt.Entity, handle string, src *et.Source) (*dbt.Entity, error) {
	return createIDClaim(sess, orgent, oamgen.ARINHandle, handle, src)
}

// FindOrgByRDAPHandle returns the organization src recorded under the handle.
func FindOrgByRDAPHandle(sess et.Session, handle string, src *et.Source) (*dbt.Entity, error) {
	return findOrgByIDClaim(sess, oamgen.ARINHandle, handle, src)
}

// CreateOrgRegistrationIDClaim records the organization's registration
// number, claimed by src. It is found again together with the jurisdiction
// (FindOrgByJurisdictionAndRegistrationIDClaim), from any source.
func CreateOrgRegistrationIDClaim(sess et.Session, orgent *dbt.Entity, regID string, src *et.Source) (*dbt.Entity, error) {
	return createIDClaim(sess, orgent, registrationIDType, regID, src)
}

// UEIIdentifier is the id_type of a SAM.gov Unique Entity ID, the identifier
// the US government issues to every entity it funds or contracts with.
const UEIIdentifier = "uei"

// CreateOrgIdentifier records an identifier the organization holds, of idType
// and value, claimed by src.
func CreateOrgIdentifier(sess et.Session, orgent *dbt.Entity, idType, value string, src *et.Source) (*dbt.Entity, error) {
	return createIDClaim(sess, orgent, idType, value, src)
}

// StoreUnambiguousIdentifier records the organization's identifier of idType
// when every record a collector matched to it by name agrees on one value. A
// name match can join the records of several entities with the same name, so
// differing values are none of them the organization's for certain, and
// nothing is stored.
func StoreUnambiguousIdentifier(sess et.Session, orgent *dbt.Entity, idType string, values []string, src *et.Source) {
	var value string
	for _, v := range values {
		v = strings.ToUpper(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if value != "" && v != value {
			return
		}
		value = v
	}
	if value != "" {
		_, _ = createIDClaim(sess, orgent, idType, value, src)
	}
}

// createIDClaim links the organization to the Identifier of idType and
// value, with src as the source of the Identifier and of the edge.
func createIDClaim(sess et.Session, orgent *dbt.Entity, idType, value string, src *et.Source) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	ident, err := sess.DB().CreateAsset(ctx, &oamgen.Identifier{
		UniqueID: idType + ":" + value,
		ID:       value,
		Type:     idType,
	})
	if err != nil || ident == nil {
		return nil, err
	}

	support.AddSource(ctx, sess, ident, src)

	if _, err := support.Relate(ctx, sess, orgent, &oamgen.SimpleRelation{Name: "id"}, ident, src); err != nil {
		return nil, err
	}

	return ident, nil
}

// findOrgByIDClaim returns the organization whose id edge to the Identifier
// of idType and value src vouches for.
func findOrgByIDClaim(sess et.Session, idType, value string, src *et.Source) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	ids, err := sess.DB().FindEntitiesByContent(ctx, oam.Identifier, time.Time{}, 1, dbt.ContentFilters{
		"id":      value,
		"id_type": idType,
	})
	if err != nil || len(ids) != 1 {
		return nil, fmt.Errorf("failed to obtain the entity for Identifier - %s:%s", idType, value)
	}

	if edges, err := sess.DB().IncomingEdges(ctx, ids[0], time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if !support.Sourced(ctx, sess, edge, time.Time{}, src) {
				continue
			}
			if o, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && o != nil {
				if _, valid := o.Asset.(*oamorg.Organization); valid {
					return o, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to obtain the Organization associated with Identifier - %s:%s", idType, value)
}

// CreateOrgJurisdictionClaim records the organization's jurisdiction (an ISO
// 3166 country or subdivision code) as a property.
func CreateOrgJurisdictionClaim(sess et.Session, orgent *dbt.Entity, jurisdiction string) error {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	if _, err := sess.DB().CreateEntityProperty(ctx, orgent, &oamgen.SimpleProperty{
		PropertyName:  "jurisdiction",
		PropertyValue: jurisdiction,
	}); err == nil {
		return nil
	}

	return fmt.Errorf("failed to create the jurisdiction claim %s for organization %s", jurisdiction, orgent.Asset.Key())
}

// jurisdictionsCompatible reports whether two jurisdictions can be the same
// registry: equal, or a country and one of its subdivisions (US and US-DE),
// or two subdivisions of one country. Case is ignored.
func jurisdictionsCompatible(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if strings.EqualFold(a, b) {
		return true
	}
	ca, _, _ := strings.Cut(a, "-")
	cb, _, _ := strings.Cut(b, "-")
	return strings.EqualFold(ca, cb)
}

// hasCompatibleJurisdiction reports whether one of the organization's
// jurisdiction claims is compatible with jurisdiction.
func hasCompatibleJurisdiction(ctx context.Context, sess et.Session, orgent *dbt.Entity, jurisdiction string) bool {
	tags, err := sess.DB().FindEntityTags(ctx, orgent, time.Time{}, "jurisdiction")
	if err != nil {
		return false
	}
	for _, tag := range tags {
		if jc, valid := tag.Property.(*oamgen.SimpleProperty); valid &&
			jurisdictionsCompatible(jurisdiction, jc.PropertyValue) {
			return true
		}
	}
	return false
}

// FindOrgByNormNameAndJurisdictionClaim returns a stored organization with
// the normalized name and a compatible jurisdiction, from any source.
func FindOrgByNormNameAndJurisdictionClaim(sess et.Session, norm, jurisdiction string) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	// Examine every stored organization sharing this normalized name, not just
	// the first: the one carrying a compatible jurisdiction may not be the
	// first row returned, and missing it creates a duplicate the evidence
	// already ruled out.
	orgents, err := sess.DB().FindEntitiesByContent(ctx, oam.Organization, time.Time{}, maxSameNameOrgs, dbt.ContentFilters{
		"name": norm,
	})
	if err != nil || len(orgents) == 0 {
		return nil, fmt.Errorf("failed to obtain organizations with norm name %s", norm)
	}

	octx, ocancel := context.WithTimeout(sess.Ctx(), time.Minute)
	defer ocancel()

	for _, orgent := range orgents {
		if hasCompatibleJurisdiction(octx, sess, orgent, jurisdiction) {
			return orgent, nil
		}
	}

	return nil, fmt.Errorf("failed to obtain the Organization associated with norm name %s and jurisdiction %s", norm, jurisdiction)
}

// FindOrgByJurisdictionAndRegistrationIDClaim returns a stored organization
// with the registration number and a compatible jurisdiction, from any
// source: a registry number names one entity in its registry.
func FindOrgByJurisdictionAndRegistrationIDClaim(sess et.Session, jurisdiction, regID string) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), time.Minute)
	defer cancel()

	ids, err := sess.DB().FindEntitiesByContent(ctx, oam.Identifier, time.Time{}, 1, dbt.ContentFilters{
		"id":      regID,
		"id_type": registrationIDType,
	})
	if err != nil || len(ids) != 1 {
		return nil, fmt.Errorf("failed to obtain the entity for Identifier - %s:%s", registrationIDType, regID)
	}

	if edges, err := sess.DB().IncomingEdges(ctx, ids[0], time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			orgent, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID)
			if err != nil || orgent == nil {
				continue
			}
			if hasCompatibleJurisdiction(ctx, sess, orgent, jurisdiction) {
				return orgent, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to obtain the Organization associated with jurisdiction %s and registration ID %s", jurisdiction, regID)
}
