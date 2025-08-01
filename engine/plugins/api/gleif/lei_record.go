// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"errors"
	"fmt"
	"strings"

	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
)

func (g *gleif) createLEIIdentifier(session et.Session, orgent *dbt.Entity, lei *general.Identifier, conf int) (*dbt.Entity, error) {
	id, err := session.Cache().CreateAsset(lei)
	if err != nil {
		return nil, err
	} else if id == nil {
		return nil, errors.New("failed to create the Identifier asset")
	}

	_, _ = session.Cache().CreateEntityProperty(id, &general.SourceProperty{
		Source:     g.source.Name,
		Confidence: conf,
	})

	if orgent != nil {
		if err := g.createRelation(session, orgent, general.SimpleRelation{Name: "id"}, id, conf); err != nil {
			return nil, err
		}
	}
	return id, nil
}

func (g *gleif) createLEIFromRecord(e *et.Event, orgent *dbt.Entity, lei *org.LEIRecord, conf int) (*dbt.Entity, error) {
	return g.createLEIIdentifier(e.Session, orgent, &general.Identifier{
		UniqueID:       fmt.Sprintf("%s:%s", general.LEICode, lei.ID),
		ID:             lei.ID,
		Type:           general.LEICode,
		Status:         lei.Attributes.Registration.Status,
		CreationDate:   lei.Attributes.Registration.InitialRegistrationDate,
		UpdatedDate:    lei.Attributes.Registration.LastUpdateDate,
		ExpirationDate: lei.Attributes.Registration.NextRenewalDate,
	}, conf)
}

func (g *gleif) buildAddrFromLEIAddress(addr *org.LEIAddress) string {
	street := strings.Join(addr.AddressLines, " ")

	province := addr.Region
	if parts := strings.Split(province, "-"); len(parts) > 1 {
		province = parts[1]
	}

	return fmt.Sprintf("%s %s %s %s %s", street, addr.City, province, addr.PostalCode, addr.Country)
}
