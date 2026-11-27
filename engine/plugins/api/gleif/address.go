// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// addresses resolves the organizations registered at a street address, the
// reverse of the model's organization -> address direction, so an enumeration
// can pivot from a StreetAddress to the organizations there. GLEIF filters
// addresses only by country and searches the street and city as full text, so
// the handler confirms the street, number and city itself and attaches only
// records whose registered address matches the seed.
type addresses struct {
	name   string
	plugin *gleif
}

func (a *addresses) check(e *et.Event) error {
	loc, ok := e.Entity.Asset.(*contact.StreetAddress)
	if !ok {
		return errors.New("failed to extract the StreetAddress asset")
	}
	// A seeded freeform address may carry only its Address string; parse it so
	// the search has a city and the street can be confirmed.
	if strings.TrimSpace(loc.City) == "" || strings.TrimSpace(loc.StreetName) == "" {
		if parsed := support.ParseStreetAddress(loc.Address); parsed != nil {
			loc = parsed
		}
	}
	// A bounded search needs the street, city and country; without them the
	// query would be too broad or unverifiable, so skip.
	country := normCountry(loc.Country)
	if loc.City == "" || loc.StreetName == "" || country == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.StreetAddress), string(oam.Organization), a.plugin.name)
	if err != nil {
		return err
	}

	src := &et.Source{Name: a.name, Confidence: a.plugin.source.Confidence}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		return nil
	}

	recs, err := GLEIFSearchByAddress(e.Session.Ctx(), e.Session.Clients().General, loc.StreetName, loc.City,
		country)
	if err != nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", a.plugin.name, "handler", a.name))
		return nil
	}

	a.process(e, a.store(e, e.Entity, loc, recs))
	support.MarkAssetMonitored(e.Session, e.Entity, src)
	return nil
}

// store creates (or reuses) the organization behind each record whose
// registered address matches the seed's street, fills it from the record, and
// ties it to the seed StreetAddress through a ContactRecord.
func (a *addresses) store(e *et.Event, seedent *dbt.Entity, seed *contact.StreetAddress, recs []*LEIRecord) []*dbt.Entity {
	var orgs []*dbt.Entity

	for _, rec := range recs {
		if !recordAtAddress(seed, rec) {
			continue
		}

		name := rec.Attributes.Entity.LegalName.Name
		if name == "" {
			continue
		}

		o := &oamorg.Organization{
			Name:           name,
			Jurisdiction:   rec.Attributes.Entity.Jurisdiction,
			RegistrationID: rec.Attributes.Entity.RegisteredAs,
		}
		orgent, err := a.getOrganization(e.Session, o, rec.ID)
		if err != nil || orgent == nil {
			continue
		}

		a.plugin.updateOrgFromLEIRecord(e, orgent, rec, a.plugin.source.Confidence)
		support.MarkAssetMonitored(e.Session, orgent, a.plugin.source)
		a.linkSeed(e, seedent, orgent, rec)
		orgs = append(orgs, orgent)
	}

	return orgs
}

// getOrganization reuses the organization already holding the LEI, or creates
// one through the shared idempotent path so a known organization is not
// duplicated.
func (a *addresses) getOrganization(sess et.Session, o *oamorg.Organization, lei string) (*dbt.Entity, error) {
	orgent, err := org.FindOrgByLEICode(sess, lei, a.plugin.source)
	if err != nil || orgent == nil {
		orgent, err = org.CreateOrgAsset(sess, nil, nil, o, a.plugin.source)
	}
	return orgent, err
}

// linkSeed ties the organization to the seed StreetAddress through a ContactRecord
// (ContactRecord --organization--> org, --location--> seed), so the pivot can
// walk from the address back to the organization.
func (a *addresses) linkSeed(e *et.Event, seedent, orgent *dbt.Entity, rec *LEIRecord) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	cr, err := e.Session.DB().CreateAsset(ctx,
		&contact.ContactRecord{DiscoveredAt: "https://api.gleif.org/api/v1/lei-records/" + rec.ID})
	if err != nil || cr == nil {
		return
	}
	support.AddSource(ctx, e.Session, cr, a.plugin.source)

	_, _ = support.Relate(ctx, e.Session, cr,
		&oamgen.SimpleRelation{Name: "organization"}, orgent, a.plugin.source)
	_, _ = support.Relate(ctx, e.Session, cr,
		&oamgen.SimpleRelation{Name: "street_address"}, seedent, a.plugin.source)
}

// process dispatches each resolved organization so the organization handlers
// (identity, website -> domain) run and the pivot can reach the domains.
func (a *addresses) process(e *et.Event, orgs []*dbt.Entity) {
	for _, orgent := range orgs {
		org.DispatchOrg(e, orgent)
	}
}

// recordAtAddress reports whether a record's legal, headquarters or other
// address matches the seed's street (and house number and city, when known),
// so a record that merely mentions the street elsewhere is not attached.
func recordAtAddress(seed *contact.StreetAddress, rec *LEIRecord) bool {
	addrs := []*LEIAddress{&rec.Attributes.Entity.LegalAddress, &rec.Attributes.Entity.HeadquartersAddress}
	for i := range rec.Attributes.Entity.OtherAddresses {
		addrs = append(addrs, &rec.Attributes.Entity.OtherAddresses[i])
	}

	for _, ad := range addrs {
		if addressLineMatches(seed, ad) {
			return true
		}
	}
	return false
}

// addressLineMatches reports whether the record address's street line contains
// the seed's street, its house number when the seed names one, and whether
// its city is the seed's when both name one.
func addressLineMatches(seed *contact.StreetAddress, ad *LEIAddress) bool {
	street := semantics.PlainText(seed.StreetName)
	if street == "" {
		return false
	}

	line := semantics.PlainText(strings.Join(ad.AddressLines, " ") + " " + ad.AddressNumber)
	if !strings.Contains(line, street) {
		return false
	}
	if n := semantics.PlainText(seed.BuildingNumber); n != "" && !strings.Contains(line, n) {
		return false
	}
	if c, rc := semantics.PlainText(seed.City), semantics.PlainText(ad.City); c != "" && rc != "" && c != rc {
		return false
	}
	return true
}
