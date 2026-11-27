// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// OrgForControlledDomain returns an existing Organization already linked to the
// domain as Organization --website--> URL --domain--> FQDN(domain), or nil when
// none is.
//
// Several organization-identity sources (Wikidata, the homepage schema.org
// markup, …) can independently recognize the same company behind one domain. The
// first to run creates the organization and the website chain; the others call
// this so they enrich that one organization instead of each creating a duplicate
// node. It only reduces duplicates — a true simultaneous race (both checking
// before either writes) still falls to the reviewed attribution/duplicates
// merge (ai-design-principles.md principle 10).
func OrgForControlledDomain(sess et.Session, domain string) *dbt.Entity {
	if domain == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(sess.Ctx(), 20*time.Second)
	defer cancel()

	// The apex FQDN exists during an enumeration; CreateAsset is idempotent and
	// returns the existing entity.
	fq, err := sess.DB().CreateAsset(ctx, &oamdns.FQDN{Name: domain})
	if err != nil || fq == nil {
		return nil
	}

	urlEdges, err := sess.DB().IncomingEdges(ctx, fq, time.Time{}, "domain")
	if err != nil {
		return nil
	}
	for _, ue := range urlEdges {
		urlent, err := sess.DB().FindEntityById(ctx, ue.FromEntity.ID)
		if err != nil || urlent == nil {
			continue
		}
		orgEdges, err := sess.DB().IncomingEdges(ctx, urlent, time.Time{}, "website")
		if err != nil {
			continue
		}
		for _, oe := range orgEdges {
			orgent, err := sess.DB().FindEntityById(ctx, oe.FromEntity.ID)
			if err != nil || orgent == nil {
				continue
			}
			if _, ok := orgent.Asset.(*oamorg.Organization); ok {
				return orgent
			}
		}
	}
	return nil
}

// LinkWebsite records an organization's website as Organization --website-->
// URL --domain--> FQDN, the chain OrgForControlledDomain reads back, with src
// as the source of the URL, the FQDN and both edges. host is the name the
// website is for. It reports whether the chain was stored.
func LinkWebsite(sess et.Session, orgent *dbt.Entity, rawURL, host string, src *et.Source) bool {
	u := support.RawURLToOAM(rawURL)
	host = strings.ToLower(strings.TrimSpace(host))
	if u == nil || host == "" {
		return false
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	urlent, err := sess.DB().CreateAsset(ctx, u)
	if err != nil || urlent == nil {
		return false
	}
	support.AddSource(ctx, sess, urlent, src)
	if _, err := support.Relate(ctx, sess, orgent, &oamgen.SimpleRelation{Name: "website"}, urlent, src); err != nil {
		return false
	}

	fq, err := sess.DB().CreateAsset(ctx, &oamdns.FQDN{Name: host})
	if err != nil || fq == nil {
		return false
	}
	support.AddSource(ctx, sess, fq, src)
	_, err = support.Relate(ctx, sess, urlent, &oamgen.SimpleRelation{Name: "domain"}, fq, src)
	return err == nil
}

// DomainIdentity is the organization a source names as a registered domain's
// owner: Wikidata by the entity whose official website is the domain, a site
// by the schema.org markup on its own homepage.
type DomainIdentity struct {
	Name      string
	LegalName string
	Country   string // ISO 3166-1 alpha-2, or a country name
	LEI       string // the Legal Entity Identifier, an exact key GLEIF enriches from
	Website   string // the website the source matched; the domain's homepage when empty
}

// BestName is the name the organization is stored under: its legal name when
// known, else its name.
func (d DomainIdentity) BestName() string {
	if n := strings.TrimSpace(d.LegalName); n != "" {
		return n
	}
	return strings.TrimSpace(d.Name)
}

// StoreDomainIdentity records the organization a source names for a domain and
// dispatches it. An organization another source already tied to the domain is
// reused, with src added as a source and its jurisdiction filled when unset,
// rather than duplicated; otherwise the organization is created and linked to
// the domain through its website. An LEI is linked and dispatched. It returns
// the organization, or nil when none was stored.
func StoreDomainIdentity(e *et.Event, domain string, id DomainIdentity, src *et.Source) *dbt.Entity {
	if id.BestName() == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	orgent := OrgForControlledDomain(e.Session, domain)
	if orgent == nil {
		var err error
		orgent, err = CreateOrgAsset(e.Session, nil, nil, &oamorg.Organization{
			Name:         id.BestName(),
			LegalName:    id.LegalName,
			Jurisdiction: id.Country,
		}, src)
		if err != nil || orgent == nil {
			return nil
		}

		website := id.Website
		if website == "" {
			website = "https://" + domain
		}
		LinkWebsite(e.Session, orgent, website, domain, src)
	} else {
		support.AddSource(ctx, e.Session, orgent, src)
		if o := orgent.Asset.(*oamorg.Organization); id.Country != "" && o.Jurisdiction == "" {
			o.Jurisdiction = id.Country
			_, _ = e.Session.DB().CreateEntity(ctx, orgent)
		}
	}

	if id.LEI != "" {
		lei := &oamgen.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", oamgen.LEICode, id.LEI),
			ID:       id.LEI,
			Type:     oamgen.LEICode,
		}
		if ident, err := e.Session.DB().CreateAsset(ctx, lei); err == nil && ident != nil {
			support.AddSource(ctx, e.Session, ident, src)
			_, _ = support.Relate(ctx, e.Session, orgent, &oamgen.SimpleRelation{Name: "id"}, ident, src)
			_ = e.Dispatcher.DispatchEvent(&et.Event{Name: lei.UniqueID, Entity: ident, Session: e.Session})
		}
	}

	DispatchOrg(e, orgent)
	return orgent
}
