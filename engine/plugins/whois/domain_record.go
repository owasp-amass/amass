// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type domrec struct {
	name       string
	plugin     *whois
	transforms []string
}

func (r *domrec) Name() string {
	return r.name
}

func (r *domrec) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamreg.DomainRecord)
	if !ok {
		return errors.New("the event did not contain a DomainRecord asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.DomainRecord), append(r.transforms, r.plugin.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	src := r.plugin.source
	var findings []*support.Finding
	if record, ok := e.Meta.(*whoisparser.WhoisInfo); ok && record != nil {
		r.store(e, record, e.Entity, matches)
	} else {
		findings = append(findings, r.lookup(e, e.Entity, src, matches)...)
	}

	if len(findings) > 0 {
		r.process(e, findings, src)
	}
	return nil
}

func (r *domrec) lookup(e *et.Event, asset *dbt.Entity, src *et.Source, m *config.Matches) []*support.Finding {
	var findings []*support.Finding

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 2*time.Minute)
	defer cancel()

	for _, atype := range r.transforms {
		if !m.IsMatch(atype) {
			continue
		}

		since, err := support.TTLStartTime(e.Session.Config(), string(oam.DomainRecord), atype, r.plugin.name)
		if err != nil {
			continue
		}

		var rtypes []string
		switch atype {
		case string(oam.FQDN):
			rtypes = append(rtypes, "name_server", "whois_server")
		case string(oam.ContactRecord):
			rtypes = append(rtypes, "registrar_contact", "registrant_contact", "admin_contact", "technical_contact", "billing_contact")
		}

		if edges, err := e.Session.DB().OutgoingEdges(ctx, asset, since, rtypes...); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				to, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
				if err != nil {
					continue
				}

				if !r.oneOfSources(ctx, e, to, src, since) {
					continue
				}

				dr := asset.Asset.(*oamreg.DomainRecord)
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: "DomainRecord: " + dr.Domain,
					To:       to,
					ToName:   to.Asset.Key(),
					Rel:      edge.Relation,
				})
			}
		}
	}

	return findings
}

func (r *domrec) oneOfSources(ctx context.Context, e *et.Event, asset *dbt.Entity, src *et.Source, since time.Time) bool {
	if tags, err := e.Session.DB().FindEntityTags(ctx, asset, since, src.Name); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if _, ok := tag.Property.(*general.SourceProperty); ok {
				return true
			}
		}
	}
	return false
}

func (r *domrec) store(e *et.Event, resp *whoisparser.WhoisInfo, asset *dbt.Entity, m *config.Matches) {
	var findings []*support.Finding
	dr := asset.Asset.(*oamreg.DomainRecord)

	if !m.IsMatch(string(oam.FQDN)) {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	for _, ns := range resp.Domain.NameServers {
		for _, name := range support.ScrapeSubdomainNames(strings.ToLower(strings.TrimSpace(ns))) {
			if a, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name}); err == nil && a != nil {
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: "DomainRecord: " + dr.Domain,
					To:       a,
					ToName:   name,
					Rel:      &general.SimpleRelation{Name: "name_server"},
				})
			}
		}
	}
	if name := dr.WhoisServer; name != "" && len(support.ScrapeSubdomainNames(name)) > 0 {
		if a, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name}); err == nil && a != nil {
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "DomainRecord: " + dr.Domain,
				To:       a,
				ToName:   name,
				Rel:      &general.SimpleRelation{Name: "whois_server"},
			})
		}
	}

	// process the relations built above immediately
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)

	if !m.IsMatch(string(oam.ContactRecord)) {
		return
	}

	base := dr.WhoisServer + ", " + dr.Domain + ", "
	contacts := []*domrecContact{
		{resp.Registrar, "registrar_contact", base + "Registrar Contact Info"},
		{resp.Registrant, "registrant_contact", base + "Registrant Contact Info"},
		{resp.Administrative, "admin_contact", base + "Admin Contact Info"},
		{resp.Technical, "technical_contact", base + "Technical Contact Info"},
		{resp.Billing, "billing_contact", base + "Billing Contact Info"},
	}
	for _, c := range contacts {
		if c.WhoisContact != nil {
			r.storeContact(e, c, asset, m)
		}
	}
}

type domrecContact struct {
	WhoisContact *whoisparser.Contact
	RelationName string
	DiscoveredAt string
}

func (r *domrec) storeContact(e *et.Event, c *domrecContact, dr *dbt.Entity, m *config.Matches) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Minute)
	defer cancel()

	cr, err := e.Session.DB().CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: c.DiscoveredAt})
	if err != nil || cr == nil {
		return
	}

	var found bool
	wc := c.WhoisContact
	// test if the address begins in the organization field
	addr := fmt.Sprintf("%s %s %s %s %s %s",
		wc.Organization, wc.Street, wc.City, wc.Province, wc.PostalCode, wc.Country)
	if loc := support.StreetAddressToLocation(addr); loc != nil &&
		strings.HasPrefix(loc.Building, strings.ToLower(wc.Organization)) {
		found = true
		addr = fmt.Sprintf("%s %s %s %s %s",
			wc.Street, wc.City, wc.Province, wc.PostalCode, wc.Country)
	} else {
		wc.Organization = wc.Name
	}

	if found {
		if p := support.FullNameToPerson(wc.Name); p != nil && m.IsMatch(string(oam.Person)) {
			if a, err := e.Session.DB().CreateAsset(ctx, p); err == nil && a != nil {
				r.createSimpleEdge(e.Session, &general.SimpleRelation{Name: "person"}, cr, a)
			}
		}
	}

	if loc := support.StreetAddressToLocation(addr); loc != nil {
		if a, err := e.Session.DB().CreateAsset(ctx, loc); err == nil && a != nil {
			r.createSimpleEdge(e.Session, &general.SimpleRelation{Name: "location"}, cr, a)
		}
	}
	if email := strings.ToLower(wc.Email); m.IsMatch(string(oam.Identifier)) && email != "" {
		if a, err := e.Session.DB().CreateAsset(ctx, &general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", general.EmailAddress, email),
			ID:       email,
			Type:     general.EmailAddress,
		}); err == nil && a != nil {
			r.createSimpleEdge(e.Session, &general.SimpleRelation{Name: "id"}, cr, a)
		}
	}
	if m.IsMatch(string(oam.Phone)) {
		if phone := support.PhoneToOAMPhone(wc.Phone, wc.PhoneExt, wc.Country); phone != nil {
			phone.Type = contact.PhoneTypeRegular
			if a, err := e.Session.DB().CreateAsset(ctx, phone); err == nil && a != nil {
				r.createSimpleEdge(e.Session, &general.SimpleRelation{Name: "phone"}, cr, a)
			}
		}
		if fax := support.PhoneToOAMPhone(wc.Fax, wc.FaxExt, wc.Country); fax != nil {
			fax.Type = contact.PhoneTypeFax
			if a, err := e.Session.DB().CreateAsset(ctx, fax); err == nil && a != nil {
				r.createSimpleEdge(e.Session, &general.SimpleRelation{Name: "phone"}, cr, a)
			}
		}
	}
	if u := support.RawURLToOAM(wc.ReferralURL); u != nil && m.IsMatch(string(oam.URL)) {
		if a, err := e.Session.DB().CreateAsset(ctx, u); err == nil && a != nil {
			r.createSimpleEdge(e.Session, &general.SimpleRelation{Name: "url"}, cr, a)
		}
	}

	var findings []*support.Finding
	record := dr.Asset.(*oamreg.DomainRecord)
	findings = append(findings, &support.Finding{
		From:     dr,
		FromName: "DomainRecord: " + record.Domain,
		To:       cr,
		ToName:   "ContactRecord: " + c.DiscoveredAt,
		Rel:      &general.SimpleRelation{Name: c.RelationName},
	})
	// process the contact record relation immediately
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)

	// the organization must come last due to a potential chicken-and-egg problem
	if m.IsMatch(string(oam.Organization)) {
		orgent, err := org.CreateOrgAsset(e.Session, cr,
			&general.SimpleRelation{Name: "organization"},
			&oamorg.Organization{Name: wc.Organization}, r.plugin.source)

		if err == nil && orgent != nil {
			o := orgent.Asset.(*oamorg.Organization)

			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    fmt.Sprintf("%s:%s", o.Name, o.ID),
				Entity:  orgent,
				Session: e.Session,
			})
		}
	}
}

func (r *domrec) process(e *et.Event, findings []*support.Finding, src *et.Source) {
	support.ProcessAssetsWithSource(e, findings, src, r.plugin.name, r.name)
}

func (r *domrec) createSimpleEdge(sess et.Session, rel oam.Relation, from, to *dbt.Entity) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	if edge, err := sess.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   rel,
		FromEntity: from,
		ToEntity:   to,
	}); err == nil && edge != nil {
		_, _ = sess.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
			Source:     r.plugin.source.Name,
			Confidence: r.plugin.source.Confidence,
		})
	}
}
