// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
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

func CreateOrgAsset(session et.Session, obj *dbt.Entity, rel oam.Relation, o *oamorg.Organization, src *et.Source) (*dbt.Entity, error) {
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

			o.ID = determineOrgID(name)
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

func determineOrgID(name string) string {
	var rec *LEIRecord

	if records, err := GLEIFSearchFuzzyCompletions(name); err == nil && records != nil && len(records.Data) > 0 {
		swg := metrics.NewSmithWatermanGotoh()
		swg.CaseSensitive = false
		swg.GapPenalty = -0.1
		swg.Substitution = metrics.MatchMismatch{
			Match:    1,
			Mismatch: -0.5,
		}

		var conf int
		for _, data := range records.Data {
			if data.Type != "fuzzycompletions" || data.Relationships.LEIRecords.Data.Type != "lei-records" {
				continue
			}

			match := data.Attributes.Value
			lei := data.Relationships.LEIRecords.Data.ID
			if !strings.Contains(strings.ToLower(match), strings.ToLower(name)) {
				continue
			}

			sim := strutil.Similarity(name, match, swg)
			score := int(math.Round(sim * 30))

			if len(records.Data) == 1 {
				score += 30
			}

			if score > conf {
				if r, err := GLEIFGetLEIRecord(lei); err == nil {
					rec = r
					conf = score
				}
			}
		}
	}

	if rec != nil {
		result := fmt.Sprintf("%s:%s:", rec.Attributes.Entity.LegalName.Name, rec.Attributes.Entity.Jurisdiction)

		if val := rec.Attributes.Entity.RegisteredAs; val != "" {
			result += val
		} else if val := rec.Attributes.Entity.RegisteredAt.Other; val != "" {
			result += val
		} else {
			result += rec.ID
		}

		return result
	}
	// If no LEI record is found, generate a UUID as the identifier.
	// This ensures that the organization has a unique identifier even without an LEI record
	return uuid.New().String()
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
