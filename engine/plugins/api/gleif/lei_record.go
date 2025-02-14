// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
)

func (g *gleif) getLEIRecord(ident *general.Identifier) (*leiRecord, error) {
	g.rlimit.Take()

	u := "https://api.gleif.org/api/v1/lei-records/" + ident.EntityID
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
	if err != nil || resp.Body == "" {
		return nil, err
	}

	var result singleResponse
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return nil, err
	} else if len(result.Data.ID) == 0 || result.Data.Type != "lei-records" {
		return nil, errors.New("failed to find the LEI record")
	}
	return &result.Data, nil
}

func (g *gleif) createLEIIdentifier(session et.Session, orgent *dbt.Entity, lei *general.Identifier) (*dbt.Entity, error) {
	id, err := session.Cache().CreateAsset(lei)
	if err != nil {
		return nil, err
	} else if id == nil {
		return nil, errors.New("failed to create the Identifier asset")
	}

	if orgent != nil {
		if err := g.createRelation(session, orgent, general.SimpleRelation{Name: "id"}, id); err != nil {
			return nil, err
		}
	}
	return id, nil
}

func (g *gleif) createLEIFromRecord(e *et.Event, orgent *dbt.Entity, lei *leiRecord) (*dbt.Entity, error) {
	return g.createLEIIdentifier(e.Session, orgent, &general.Identifier{
		UniqueID:       fmt.Sprintf("%s:%s", general.LEICode, lei.ID),
		EntityID:       lei.ID,
		Type:           general.LEICode,
		Status:         lei.Attributes.Registration.Status,
		CreationDate:   lei.Attributes.Registration.InitialRegistrationDate,
		UpdatedDate:    lei.Attributes.Registration.LastUpdateDate,
		ExpirationDate: lei.Attributes.Registration.NextRenewalDate,
	})
}
