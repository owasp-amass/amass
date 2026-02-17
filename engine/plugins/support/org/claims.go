// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func CreateOrgNameClaim(sess et.Session, orgent *dbt.Entity, name string, src *et.Source) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	id := &oamgen.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", oamgen.OrganizationName, name),
		ID:       name,
		Type:     oamgen.OrganizationName,
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

func FindOrgByNameClaim(sess et.Session, name string, src *et.Source) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	ids, err := sess.DB().FindEntitiesByContent(ctx, oam.Identifier, time.Time{}, 1, dbt.ContentFilters{
		"id":      name,
		"id_type": oamgen.OrganizationName,
	})
	if err != nil || len(ids) != 1 {
		return nil, fmt.Errorf("failed to obtain the entity for Identifier - %s:%s", oamgen.OrganizationName, name)
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

	return nil, fmt.Errorf("failed to obtain the Organization associated with Identifier - %s:%s", oamgen.OrganizationName, name)
}

func CreateOrgLegalNameClaim(sess et.Session, orgent *dbt.Entity, name string, src *et.Source) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	id := &oamgen.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", oamgen.LegalName, name),
		ID:       name,
		Type:     oamgen.LegalName,
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

func FindOrgByLegalNameClaim(sess et.Session, name string, src *et.Source) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	ids, err := sess.DB().FindEntitiesByContent(ctx, oam.Identifier, time.Time{}, 1, dbt.ContentFilters{
		"id":      name,
		"id_type": oamgen.LegalName,
	})
	if err != nil || len(ids) != 1 {
		return nil, fmt.Errorf("failed to obtain the entity for Identifier - %s:%s", oamgen.LegalName, name)
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

	return nil, fmt.Errorf("failed to obtain the Organization associated with Identifier - %s:%s", oamgen.LegalName, name)
}

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

func FindOrgByNormNameAndJurisdictionClaim(sess et.Session, norm, jurisdiction string) (*dbt.Entity, error) {
	var country string
	if parts := strings.Split(jurisdiction, "-"); len(parts) == 2 {
		country = parts[0]
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	orgents, err := sess.DB().FindEntitiesByContent(ctx, oam.Organization, time.Time{}, 1, dbt.ContentFilters{
		"name": norm,
	})
	if err != nil || len(orgents) == 0 {
		return nil, fmt.Errorf("failed to obtain organizations with norm name %s", norm)
	}

	seconds := 10 * len(orgents)
	octx, ocancel := context.WithTimeout(sess.Ctx(), time.Duration(seconds)*time.Second)
	defer ocancel()

	for _, orgent := range orgents {
		tags, err := sess.DB().FindEntityTags(octx, orgent, time.Time{}, "jurisdiction")
		if err != nil || len(tags) == 0 {
			continue
		}

		for _, tag := range tags {
			jc, valid := tag.Property.(*oamgen.SimpleProperty)
			if !valid {
				continue
			}
			jv := jc.PropertyValue

			if strings.EqualFold(jurisdiction, jv) {
				return orgent, nil
			} else if country != "" && strings.EqualFold(country, jv) {
				return orgent, nil
			} else if parts := strings.Split(jv, "-"); len(parts) == 2 && strings.EqualFold(jurisdiction, parts[0]) {
				return orgent, nil
			} else if len(parts) == 2 && strings.EqualFold(country, parts[0]) {
				return orgent, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to obtain the Organization associated with norm name %s and jurisdiction %s", norm, jurisdiction)
}

func CreateOrgRegistrationIDClaim(sess et.Session, orgent *dbt.Entity, regID string, src *et.Source) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	id := &oamgen.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", "registration_id", regID),
		ID:       regID,
		Type:     "registration_id",
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

func FindOrgByJurisdictionAndRegistrationIDClaim(sess et.Session, jurisdiction, regID string) (*dbt.Entity, error) {
	var country string
	if parts := strings.Split(jurisdiction, "-"); len(parts) == 2 {
		country = parts[0]
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), time.Minute)
	defer cancel()

	ids, err := sess.DB().FindEntitiesByContent(ctx, oam.Identifier, time.Time{}, 1, dbt.ContentFilters{
		"id":      regID,
		"id_type": "registration_id",
	})
	if err != nil || len(ids) != 1 {
		return nil, fmt.Errorf("failed to obtain the entity for Identifier - %s:%s", "registration_id", regID)
	}

	for _, ident := range ids {
		if edges, err := sess.DB().IncomingEdges(ctx, ident, time.Time{}, "id"); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				orgent, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID)
				if err != nil || orgent == nil {
					continue
				}

				tags, err := sess.DB().FindEntityTags(ctx, orgent, time.Time{}, "jurisdiction")
				if err != nil || len(tags) == 0 {
					continue
				}

				for _, tag := range tags {
					jc, valid := tag.Property.(*oamgen.SimpleProperty)
					if !valid {
						continue
					}
					jv := jc.PropertyValue

					if strings.EqualFold(jurisdiction, jv) {
						return orgent, nil
					} else if country != "" && strings.EqualFold(country, jv) {
						return orgent, nil
					} else if parts := strings.Split(jv, "-"); len(parts) == 2 && strings.EqualFold(jurisdiction, parts[0]) {
						return orgent, nil
					} else if len(parts) == 2 && strings.EqualFold(country, parts[0]) {
						return orgent, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to obtain the Organization associated with jurisdiction %s and registration ID %s", jurisdiction, regID)
}
