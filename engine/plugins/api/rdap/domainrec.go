// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/url"
)

// domrec is the RDAP detail handler: it expands a DomainRecord into the name
// servers, WHOIS server and registration contacts the RDAP response carries.
type domrec struct {
	name       string
	plugin     *rdapPlugin
	transforms []string
}

func (r *domrec) Name() string {
	return r.name
}

func (r *domrec) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamreg.DomainRecord)
	if !ok {
		return errors.New("failed to cast the DomainRecord asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.DomainRecord), append(r.transforms, r.plugin.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	var findings []*support.Finding
	// A fresh record arrives with the RDAP response attached; a record from
	// the TTL cache is expanded from the edges already stored.
	if record, ok := e.Meta.(*rdap.Domain); ok && record != nil {
		r.store(e, record, e.Entity, matches)
	} else {
		findings = append(findings, r.lookup(e, e.Entity, matches)...)
	}

	if len(findings) > 0 {
		r.process(e, findings)
	}
	return nil
}

func (r *domrec) lookup(e *et.Event, asset *dbt.Entity, m *config.Matches) []*support.Finding {
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
		case string(oam.URL):
			rtypes = append(rtypes, "rdap_url")
		case string(oam.FQDN):
			rtypes = append(rtypes, "name_server", "whois_server")
		case string(oam.ContactRecord):
			rtypes = append(rtypes, "registrant_contact", "admin_contact", "technical_contact",
				"billing_contact", "registrar_contact")
		}
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().OutgoingEdges(ctx, asset, time.Time{}, rtypes...); err == nil && len(edges) > 0 {
		dr := asset.Asset.(*oamreg.DomainRecord)
		for _, edge := range edges {
			a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
			if err != nil {
				continue
			}
			totype := string(a.Asset.AssetType())

			since, ok := sinces[totype]
			if !ok || a.LastSeen.Before(since) {
				continue
			}
			if !r.oneOfSources(e, edge, r.plugin.source, since) {
				continue
			}

			var name string
			switch v := a.Asset.(type) {
			case *oamdns.FQDN:
				name = v.Name
			case *contact.ContactRecord:
				name = "ContactRecord: " + v.DiscoveredAt
			case *url.URL:
				name = v.Raw
			default:
				continue
			}

			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "DomainRecord: " + dr.Domain,
				To:       a,
				ToName:   name,
				Rel:      edge.Relation,
			})
		}
	}

	return findings
}

func (r *domrec) oneOfSources(e *et.Event, edge *dbt.Edge, src *et.Source, since time.Time) bool {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	if tags, err := e.Session.DB().FindEdgeTags(ctx, edge, since, src.Name); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if _, ok := tag.Property.(*general.SourceProperty); ok {
				return true
			}
		}
	}
	return false
}

func (r *domrec) store(e *et.Event, resp *rdap.Domain, entity *dbt.Entity, m *config.Matches) {
	var findings []*support.Finding
	dr := entity.Asset.(*oamreg.DomainRecord)
	from := "DomainRecord: " + dr.Domain

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if u := r.plugin.getJSONLink(resp.Links); u != nil && m.IsMatch(string(oam.URL)) {
		if a, err := e.Session.DB().CreateAsset(ctx, u); err == nil && a != nil {
			findings = append(findings, &support.Finding{
				From: entity, FromName: from, To: a, ToName: u.Raw,
				Rel: &general.SimpleRelation{Name: "rdap_url"},
			})
		}
	}

	if m.IsMatch(string(oam.FQDN)) {
		for _, ns := range resp.Nameservers {
			findings = append(findings, r.fqdnFinding(ctx, e, entity, from, ns.LDHName, "name_server")...)
		}
		findings = append(findings, r.fqdnFinding(ctx, e, entity, from, dr.WhoisServer, "whois_server")...)
	}

	// process the name servers, WHOIS server and URL built above
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)

	if m.IsMatch(string(oam.ContactRecord)) {
		for _, v := range resp.Entities {
			r.plugin.storeEntity(e, 1, &v, entity, r.plugin.source, m)
		}
	}
}

// fqdnFinding creates an in-scope FQDN and the edge from the domain record to
// it, returning the finding to process, or nothing when the name is empty or
// out of scope.
func (r *domrec) fqdnFinding(ctx context.Context, e *et.Event, entity *dbt.Entity, from, name, rel string) []*support.Finding {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return nil
	}

	fqdn := &oamdns.FQDN{Name: name}
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf <= 0 {
		return nil
	}

	a, err := e.Session.DB().CreateAsset(ctx, fqdn)
	if err != nil || a == nil {
		return nil
	}
	return []*support.Finding{{
		From: entity, FromName: from, To: a, ToName: name,
		Rel: &general.SimpleRelation{Name: rel},
	}}
}

func (r *domrec) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)
}
