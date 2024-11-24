// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"errors"
	"fmt"
	"strings"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/org"
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
		return errors.New("failed to extract the DomainRecord asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.DomainRecord), append(r.transforms, r.plugin.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	src := r.plugin.source
	var findings []*support.Finding
	if record, ok := e.Meta.(*whoisparser.WhoisInfo); ok && record != nil {
		findings = append(findings, r.store(e, record, e.Entity, src, matches)...)
	} else {
		findings = append(findings, r.lookup(e, e.Entity, src, matches)...)
	}

	if len(findings) > 0 {
		r.process(e, findings, src)
	}
	return nil
}

func (r *domrec) lookup(e *et.Event, asset *dbt.Entity, src *et.Source, m *config.Matches) []*support.Finding {
	var rtypes []string
	var findings []*support.Finding
	sinces := make(map[string]time.Time)

	for _, atype := range r.transforms {
		if !m.IsMatch(atype) {
			continue
		}

		since, err := support.TTLStartTime(e.Session.Config(), string(oam.DomainRecord), atype, r.plugin.name)
		if err != nil {
			continue
		}
		sinces[atype] = since

		switch atype {
		case string(oam.FQDN):
			rtypes = append(rtypes, "name_server", "whois_server")
		case string(oam.ContactRecord):
			rtypes = append(rtypes, "registrant_contact", "admin_contact", "technical_contact", "billing_contact")
		}
	}

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		if rels, err := e.Session.DB().OutgoingRelations(asset, time.Time{}, rtypes...); err == nil && len(rels) > 0 {
			for _, rel := range rels {
				a, err := e.Session.DB().FindById(rel.ToAsset.ID, time.Time{})
				if err != nil {
					continue
				}
				totype := string(a.Asset.AssetType())

				since, ok := sinces[totype]
				if !ok || (ok && a.LastSeen.Before(since)) {
					continue
				}

				if !r.oneOfSources(e, a, src, since) {
					continue
				}

				dr := asset.Asset.(*oamreg.DomainRecord)
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: "DomainRecord: " + dr.Domain,
					To:       a,
					ToName:   a.Asset.Key(),
					Rel:      rel.Type,
				})
			}
		}
	})
	<-done
	close(done)
	return findings
}

func (r *domrec) oneOfSources(e *et.Event, asset *dbt.Entity, src *et.Source, since time.Time) bool {
	if rels, err := e.Session.DB().OutgoingRelations(asset, since, "source"); err == nil && len(rels) > 0 {
		for _, rel := range rels {
			if rel.ToAsset.ID == src.ID {
				return true
			}
		}
	}
	return false
}

func (r *domrec) store(e *et.Event, resp *whoisparser.WhoisInfo, asset, src *dbt.Asset, m *config.Matches) []*support.Finding {
	dr := asset.Asset.(*oamreg.DomainRecord)

	var findings []*support.Finding
	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		if !m.IsMatch(string(oam.FQDN)) {
			return
		}

		for _, ns := range resp.Domain.NameServers {
			for _, name := range support.ScrapeSubdomainNames(strings.ToLower(strings.TrimSpace(ns))) {
				if a, err := e.Session.DB().Create(asset, "name_server", &domain.FQDN{Name: name}); err == nil && a != nil {
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "DomainRecord: " + dr.Domain,
						To:       a,
						ToName:   name,
						Rel:      "name_server",
					})
					_, _ = e.Session.DB().Link(a, "source", src)
				}
			}
		}
		if name := dr.WhoisServer; name != "" && len(support.ScrapeSubdomainNames(name)) > 0 {
			if a, err := e.Session.DB().Create(asset, "whois_server", &domain.FQDN{Name: name}); err == nil && a != nil {
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: "DomainRecord: " + dr.Domain,
					To:       a,
					ToName:   name,
					Rel:      "whois_server",
				})
				_, _ = e.Session.DB().Link(a, "source", src)
			}
		}
	})
	<-done
	close(done)

	if !m.IsMatch(string(oam.ContactRecord)) {
		return findings
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
			findings = append(findings, r.storeContact(e, c, asset, src, m)...)
		}
	}
	return findings
}

type domrecContact struct {
	WhoisContact *whoisparser.Contact
	RelationName string
	DiscoveredAt string
}

func (r *domrec) storeContact(e *et.Event, c *domrecContact, dr *dbt.Entity, src *et.Source, m *config.Matches) []*support.Finding {
	var findings []*support.Finding

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		cr, err := e.Session.DB().Create(dr, c.RelationName, &contact.ContactRecord{DiscoveredAt: c.DiscoveredAt})
		if err != nil || cr == nil {
			return
		}

		record := dr.Asset.(*oamreg.DomainRecord)
		findings = append(findings, &support.Finding{
			From:     dr,
			FromName: "DomainRecord: " + record.Domain,
			To:       cr,
			ToName:   "ContactRecord" + c.DiscoveredAt,
			Rel:      c.RelationName,
		})
		_, _ = e.Session.DB().Link(cr, "source", src)

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
				if a, err := e.Session.DB().Create(cr, "person", p); err == nil && a != nil {
					_, _ = e.Session.DB().Link(a, "source", src)
				}
			}
		}
		if wc.Organization != "" && m.IsMatch(string(oam.Organization)) {
			if a, err := e.Session.DB().Create(cr, "organization",
				&org.Organization{Name: wc.Organization}); err == nil && a != nil {
				_, _ = e.Session.DB().Link(a, "source", src)
			}
		}
		if loc := support.StreetAddressToLocation(addr); loc != nil {
			if a, err := e.Session.DB().Create(cr, "location", loc); err == nil && a != nil {
				_, _ = e.Session.DB().Link(a, "source", src)
			}
		}
		if email := support.EmailToOAMEmailAddress(wc.Email); email != nil && m.IsMatch(string(oam.EmailAddress)) {
			if a, err := e.Session.DB().Create(cr, "email", email); err == nil && a != nil {
				_, _ = e.Session.DB().Link(a, "source", src)
			}
		}
		if m.IsMatch(string(oam.Phone)) {
			if phone := support.PhoneToOAMPhone(wc.Phone, wc.PhoneExt, wc.Country); phone != nil {
				phone.Type = contact.PhoneTypeRegular
				if a, err := e.Session.DB().Create(cr, "phone", phone); err == nil && a != nil {
					_, _ = e.Session.DB().Link(a, "source", src)
				}
			}
			if fax := support.PhoneToOAMPhone(wc.Fax, wc.FaxExt, wc.Country); fax != nil {
				fax.Type = contact.PhoneTypeFax
				if a, err := e.Session.DB().Create(cr, "phone", fax); err == nil && a != nil {
					_, _ = e.Session.DB().Link(a, "source", src)
				}
			}
		}
		if u := support.RawURLToOAM(wc.ReferralURL); u != nil && m.IsMatch(string(oam.URL)) {
			if a, err := e.Session.DB().Create(cr, "url", u); err == nil && a != nil {
				_, _ = e.Session.DB().Link(a, "source", src)
			}
		}
	})
	<-done
	close(done)
	return findings
}

func (r *domrec) process(e *et.Event, findings []*support.Finding, src *et.Source) {
	support.ProcessAssetsWithSource(e, findings, src, r.plugin.name, r.name)
}
