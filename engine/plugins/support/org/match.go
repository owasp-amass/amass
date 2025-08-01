// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

var acronyms []string = []string{
	"Inc",
	"inc",
	"INC",
	"incorporated",
	"Incorporated",
	"INCORPORATED",
	"Co",
	"co",
	"CO",
	"LLC",
	"Llc",
	"llc",
	"LTD",
	"Ltd",
	"ltd",
	"PLC",
	"Plc",
	"plc",
	"SA",
	"sa",
	`S\.A\.`,
	`s\.a\.`,
	"AG",
	"ag",
	"GmbH",
	"gmbh",
	"AB",
	"Ab",
	"ab",
	"Oy",
	"OY",
	"oy",
	"ECI",
	"eci",
	"SARL",
	`SA\sRL`,
	"sarl",
	`sa\srl`,
	`S\.A\.R\.L`,
	`S\.A\.\sR\.L`,
	`s\.a\.r\.l`,
	`s\.a\.\sr\.l`,
}

// ExtractBrandName extracts the brand name from a given organization name.
func ExtractBrandName(name string) string {
	start := `([a-zA-Z0-9]{1}[\sa-zA-Z0-9.\-']+)([,\s]{1,3})`
	exp := start + "(" + strings.Join(acronyms, "|") + `)?([.,\s]{0,3})$`
	re := regexp.MustCompile(exp)

	matches := re.FindStringSubmatch(name)
	if len(matches) < 5 {
		return name
	}
	return strings.TrimSpace(matches[1])
}

// NameMatch checks if the provided organization entity matches any of the given names.
func NameMatch(session et.Session, orgent *dbt.Entity, names []string) ([]string, []string, bool) {
	var found bool
	var exact, partial []string

	if orgent == nil || len(names) == 0 {
		return exact, partial, found
	}

	o, ok := orgent.Asset.(*org.Organization)
	if !ok {
		return exact, partial, found
	}

	var orgNames []string
	if o.Name != "" {
		orgNames = append(orgNames, o.Name)
	}
	if o.LegalName != "" {
		orgNames = append(orgNames, o.LegalName)
	}

	if edges, err := session.Cache().OutgoingEdges(orgent, time.Time{}, "id"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if id, ok := a.Asset.(*general.Identifier); ok &&
					(id.Type == general.OrganizationName || id.Type == general.LegalName) {
					orgNames = append(orgNames, id.ID)
				}
			}
		}
	}

	swg := metrics.NewSmithWatermanGotoh()
	swg.CaseSensitive = false
	swg.GapPenalty = -0.1
	swg.Substitution = metrics.MatchMismatch{
		Match:    1,
		Mismatch: -0.5,
	}

	for _, orgname := range orgNames {
		var remaining []string

		for _, name := range names {
			if strings.EqualFold(orgname, name) {
				found = true
				exact = append(exact, name)
			} else {
				remaining = append(remaining, name)
			}
		}

		for _, name := range remaining {
			if score := strutil.Similarity(orgname, name, swg); score >= 0.85 {
				found = true
				partial = append(partial, name)
			}
		}
	}

	return exact, partial, found
}

func orgsWithSameNames(session et.Session, names []string) ([]*dbt.Entity, error) {
	var idents []*dbt.Entity

	for _, n := range names {
		if n == "" {
			continue
		}
		name := strings.ToLower(n)

		// check for known organization name identifiers
		if assets, err := session.Cache().FindEntitiesByContent(&general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", general.OrganizationName, name),
			ID:       name,
			Type:     general.OrganizationName,
		}, time.Time{}); err == nil {
			for _, a := range assets {
				if _, ok := a.Asset.(*general.Identifier); ok {
					idents = append(idents, a)
				}
			}
		}

		// check for known legal name identifiers
		if assets, err := session.Cache().FindEntitiesByContent(&general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", general.LegalName, name),
			ID:       name,
			Type:     general.LegalName,
		}, time.Time{}); err == nil {
			for _, a := range assets {
				if _, ok := a.Asset.(*general.Identifier); ok {
					idents = append(idents, a)
				}
			}
		}
	}

	var orgents []*dbt.Entity
	for _, ident := range idents {
		if edges, err := session.Cache().IncomingEdges(ident, time.Time{}, "id"); err == nil {
			for _, edge := range edges {
				if a, err := session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*org.Organization); ok {
						orgents = append(orgents, a)
					}
				}
			}
		}
	}

	if len(orgents) == 0 {
		return nil, errors.New("no matching organizations were found")
	}
	return orgents, nil
}
