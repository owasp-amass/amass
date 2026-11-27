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
	"github.com/owasp-amass/amass/v5/internal/registrant"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
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
		dr := e.Entity.Asset.(*oamreg.DomainRecord)
		findings = support.StoredFindings(e, e.Entity, "DomainRecord: "+dr.Domain, r.plugin.name, matches,
			map[string][]string{
				string(oam.FQDN): {"name_server", "whois_server"},
				string(oam.ContactRecord): {"registrar_contact", "registrant_contact", "admin_contact",
					"technical_contact", "billing_contact"},
			}, src)
	}

	if len(findings) > 0 {
		r.process(e, findings, src)
	}
	return nil
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
		if c.WhoisContact != nil &&
			(c.RelationName != "registrant_contact" || !r.hasPlaceholders(c.WhoisContact)) {
			r.storeContact(e, c, asset, m)
		}
	}
}

// contactOrganization decides which WHOIS contact field names the
// organization, and returns it with the street address to store and whether
// the contact's name is a separate person. Some registries put the first
// line of the street address in the organization field; the address parser
// shows that when the organization is not the building it parses. Only then
// is the contact's name taken as the organization. When the address cannot
// be parsed, including when the parser is unavailable, the organization is
// kept as the record gives it: replacing it with the contact's name would
// record a person (an EDUCAUSE admin contact) as an organization.
func contactOrganization(wc *whoisparser.Contact, parse func(string) *contact.StreetAddress) (string, string, bool) {
	orgName := strings.TrimSpace(wc.Organization)
	rest := fmt.Sprintf("%s %s %s %s %s", wc.Street, wc.City, wc.Province, wc.PostalCode, wc.Country)
	if orgName == "" {
		return "", rest, true
	}

	loc := parse(orgName + " " + rest)
	switch {
	case loc == nil:
		return orgName, rest, true
	case strings.HasPrefix(loc.Building, strings.ToLower(orgName)):
		return orgName, rest, true
	default:
		// the organization field begins the street address
		return wc.Name, orgName + " " + rest, false
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

	wc := c.WhoisContact
	orgName, addr, found := contactOrganization(wc, support.ParseStreetAddress)
	// what the contact's name names: when the organization field begins the
	// street address, the name is the only organization name there may be
	var orgs []string
	if found && orgName != "" {
		orgs = []string{orgName}
	}
	kind, why, p := support.NameKind(e.Session, wc.Name, orgs, []string{wc.Email})
	switch kind {
	case semantics.NameKindPerson:
		if m.IsMatch(string(oam.Person)) {
			support.LinkContactPerson(e, cr, p, r.plugin.source)
		}
	case semantics.NameKindOrganization:
		if found && m.IsMatch(string(oam.Organization)) {
			org.LinkContactOrg(e, cr, wc.Name, r.plugin.source)
		}
	case semantics.NameKindUncertain:
		support.KeepUncertainName(ctx, e.Session, cr, "person", wc.Name, why, r.plugin.source)
	}
	if !found && kind != semantics.NameKindOrganization {
		// the name is not an organization's
		orgName = ""
	}
	support.StoreContact(ctx, e.Session, cr, support.Contact{
		Address:  addr,
		Email:    wc.Email,
		Phone:    wc.Phone,
		PhoneExt: wc.PhoneExt,
		Fax:      wc.Fax,
		FaxExt:   wc.FaxExt,
		Country:  wc.Country,
		URL:      wc.ReferralURL,
	}, r.plugin.source, m)

	record := dr.Asset.(*oamreg.DomainRecord)
	// process the contact record relation immediately
	support.ProcessAssetsWithSource(e, []*support.Finding{{
		From:     dr,
		FromName: "DomainRecord: " + record.Domain,
		To:       cr,
		ToName:   "ContactRecord: " + c.DiscoveredAt,
		Rel:      &general.SimpleRelation{Name: c.RelationName},
	}}, r.plugin.source, r.plugin.name, r.name)

	if orgName != "" && m.IsMatch(string(oam.Organization)) {
		org.LinkContactOrg(e, cr, orgName, r.plugin.source)
	}
}

func (r *domrec) process(e *et.Event, findings []*support.Finding, src *et.Source) {
	support.ProcessAssetsWithSource(e, findings, src, r.plugin.name, r.name)
}

func (r *domrec) hasPlaceholders(contact *whoisparser.Contact) bool {
	fields := []string{
		contact.Name,
		contact.Organization,
		contact.Street,
		contact.City,
		contact.Province,
		contact.Phone,
		contact.Fax,
		contact.Email,
	}

	for _, field := range fields {
		if d := registrant.DetectRegistrantPlaceholder(field); d.IsPlaceholder {
			return true
		}
	}
	return false
}
