// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

var createOrgLock sync.Mutex
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
	"Corp",
	"corp",
	"CORP",
	"Corporation",
	"corporation",
	"Corporated",
	"corporated",
	"LLC",
	"Llc",
	"llc",
	"Limited",
	"LIMITED",
	"limited",
	`PRIVATE\sLIMITED`,
	`Private\sLimited`,
	`private\slimited`,
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

func createOrgUnlock() {
	go func() {
		time.Sleep(2 * time.Second)
		createOrgLock.Unlock()
	}()
}

func ExtractBrandName(name string) string {
	start := `([a-zA-Z0-9]{1}[\sa-zA-Z0-9.-']+)([,\s]{1,3})`
	exp := start + "(" + strings.Join(acronyms, "|") + `)?([.,\s]{0,3})$`
	re := regexp.MustCompile(exp)

	matches := re.FindStringSubmatch(name)
	if len(matches) < 5 {
		return name
	}
	return strings.TrimSpace(matches[1])
}

func CreateOrgAsset(session et.Session, obj *dbt.Entity, rel oam.Relation, o *org.Organization, src *et.Source) (*dbt.Entity, error) {
	createOrgLock.Lock()
	defer createOrgUnlock()

	if o == nil || o.Name == "" {
		return nil, errors.New("missing the organization name")
	} else if src == nil {
		return nil, errors.New("missing the source")
	}

	var orgent *dbt.Entity
	if obj != nil {
		orgent = orgDedupChecks(session, obj, o)
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

	if obj != nil && rel != nil {
		if err := createRelation(session, obj, rel, orgent, src); err != nil {
			return nil, err
		}
	}

	return orgent, nil
}

func orgDedupChecks(session et.Session, obj *dbt.Entity, o *org.Organization) *dbt.Entity {
	var names []string

	for _, name := range []string{o.Name, o.LegalName} {
		if name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}

	switch obj.Asset.(type) {
	case *contact.ContactRecord:
		if org, found := orgNameExistsInContactRecord(session, obj, names); found {
			return org
		}
		if org, err := orgExistsAndSharesLocEntity(session, obj, o); err == nil {
			return org
		}
		if org, err := orgExistsAndSharesAncestorEntity(session, obj, o); err == nil {
			return org
		}
		if org, err := orgExistsAndHasAncestorInSession(session, o); err == nil {
			return org
		}
	case *org.Organization:
		if org, found := orgNameRelatedToOrganization(session, obj, names); found {
			return org
		}
		if org, err := orgExistsAndSharesLocEntity(session, obj, o); err == nil {
			return org
		}
		if org, err := orgExistsAndSharesAncestorEntity(session, obj, o); err == nil {
			return org
		}
		if org, err := orgExistsAndHasAncestorInSession(session, o); err == nil {
			return org
		}
	}

	return nil
}

func OrganizationNameMatch(session et.Session, orgent *dbt.Entity, names []string) ([]string, []string, bool) {
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

func orgNameExistsInContactRecord(session et.Session, cr *dbt.Entity, names []string) (*dbt.Entity, bool) {
	if cr == nil {
		return nil, false
	}

	if edges, err := session.Cache().OutgoingEdges(cr, time.Time{}, "organization"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					if _, _, found := OrganizationNameMatch(session, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	return nil, false
}

func orgNameRelatedToOrganization(session et.Session, orgent *dbt.Entity, names []string) (*dbt.Entity, bool) {
	if orgent == nil {
		return nil, false
	}

	if edges, err := session.Cache().IncomingEdges(orgent, time.Time{}, "subsidiary"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					if _, _, found := OrganizationNameMatch(session, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	if edges, err := session.Cache().OutgoingEdges(orgent, time.Time{}, "subsidiary"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					if _, _, found := OrganizationNameMatch(session, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	return nil, false
}

func orgExistsAndSharesLocEntity(session et.Session, obj *dbt.Entity, o *org.Organization) (*dbt.Entity, error) {
	var locs []*dbt.Entity

	if edges, err := session.Cache().OutgoingEdges(obj, time.Time{}, "legal_address", "hq_address", "location"); err == nil {
		for _, edge := range edges {
			if a, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*contact.Location); ok {
					locs = append(locs, a)
				}
			}
		}
	}

	var orgents, crecords []*dbt.Entity
	for _, loc := range locs {
		if edges, err := session.Cache().IncomingEdges(loc, time.Time{}, "legal_address", "hq_address", "location"); err == nil {
			for _, edge := range edges {
				if a, err := session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*contact.ContactRecord); ok && a.ID != obj.ID {
						crecords = append(crecords, a)
					} else if _, ok := a.Asset.(*org.Organization); ok && a.ID != obj.ID {
						orgents = append(orgents, a)
					}
				}
			}
		}
	}

	for _, cr := range crecords {
		if edges, err := session.Cache().OutgoingEdges(cr, time.Time{}, "organization"); err == nil {
			for _, edge := range edges {
				if a, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*org.Organization); ok {
						orgents = append(orgents, a)
					}
				}
			}
		}
	}

	for _, orgent := range orgents {
		if _, _, found := OrganizationNameMatch(session, orgent, []string{o.Name, o.LegalName}); found {
			return orgent, nil
		}
	}

	return nil, errors.New("no matching org found")
}

func orgExistsAndSharesAncestorEntity(session et.Session, obj *dbt.Entity, o *org.Organization) (*dbt.Entity, error) {
	orgents, err := orgsWithSameNames(session, []string{o.Name, o.LegalName})
	if err != nil {
		return nil, err
	}

	assets := []*dbt.Entity{obj}
	ancestors := make(map[string]struct{})
	ancestors[obj.ID] = struct{}{}
	for i := 0; i < 10 && len(assets) > 0; i++ {
		remaining := assets
		assets = []*dbt.Entity{}

		for _, r := range remaining {
			if edges, err := session.Cache().IncomingEdges(r, time.Time{}); err == nil {
				for _, edge := range edges {
					if a, err := session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
						if _, found := ancestors[a.ID]; !found {
							ancestors[a.ID] = struct{}{}
							assets = append(assets, a)
						}
					}
				}
			}
		}
	}

	for _, orgent := range orgents {
		assets = []*dbt.Entity{orgent}

		for i := 0; i < 10 && len(assets) > 0; i++ {
			remaining := assets
			assets = []*dbt.Entity{}

			for _, r := range remaining {
				if edges, err := session.Cache().IncomingEdges(r, time.Time{}); err == nil {
					for _, edge := range edges {
						if a, err := session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
							if _, found := ancestors[a.ID]; !found {
								assets = append(assets, a)
							} else {
								return orgent, nil
							}
						}
					}
				}
			}
		}
	}

	return nil, errors.New("no matching org found")
}

func orgExistsAndHasAncestorInSession(session et.Session, o *org.Organization) (*dbt.Entity, error) {
	orgents, err := orgsWithSameNames(session, []string{o.Name, o.LegalName})
	if err != nil {
		return nil, err
	}

	for _, orgent := range orgents {
		assets := []*dbt.Entity{orgent}

		for i := 0; i < 10 && len(assets) > 0; i++ {
			remaining := assets
			assets = []*dbt.Entity{}

			for _, r := range remaining {
				if edges, err := session.Cache().IncomingEdges(r, time.Time{}); err == nil {
					for _, edge := range edges {
						if a, err := session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
							if session.Queue().Has(edge.FromEntity) {
								return orgent, nil
							}
							assets = append(assets, a)
						}
					}
				}
			}
		}
	}

	return nil, errors.New("no matching org found")
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
