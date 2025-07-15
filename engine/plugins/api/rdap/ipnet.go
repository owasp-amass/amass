// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"errors"
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

type ipnet struct {
	name       string
	plugin     *rdapPlugin
	transforms []string
}

func (r *ipnet) Name() string {
	return r.name
}

func (r *ipnet) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamreg.IPNetRecord)
	if !ok {
		return errors.New("failed to extract the IPNetRecord asset")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.IPNetRecord), append(r.transforms, r.plugin.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	var findings []*support.Finding
	if record, ok := e.Meta.(*rdap.IPNetwork); ok && record != nil {
		r.store(e, record, e.Entity, matches)
	} else {
		findings = append(findings, r.lookup(e, e.Entity, matches)...)
	}

	if len(findings) > 0 {
		r.process(e, findings)
	}
	return nil
}

func (r *ipnet) lookup(e *et.Event, asset *dbt.Entity, m *config.Matches) []*support.Finding {
	var rtypes []string
	var findings []*support.Finding
	sinces := make(map[string]time.Time)

	for _, atype := range r.transforms {
		if !m.IsMatch(atype) {
			continue
		}

		since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPNetRecord), atype, r.plugin.name)
		if err != nil {
			continue
		}
		sinces[atype] = since

		switch atype {
		case string(oam.URL):
			rtypes = append(rtypes, "rdap_url")
		case string(oam.FQDN):
			rtypes = append(rtypes, "whois_server")
		case string(oam.ContactRecord):
			rtypes = append(rtypes, "registrant", "admin_contact", "abuse_contact", "technical_contact")
		}
	}

	if edges, err := e.Session.Cache().OutgoingEdges(asset, time.Time{}, rtypes...); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID)
			if err != nil {
				continue
			}
			totype := string(a.Asset.AssetType())

			since, ok := sinces[totype]
			if !ok || (ok && a.LastSeen.Before(since)) {
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

			iprec := asset.Asset.(*oamreg.IPNetRecord)
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "IPNetRecord: " + iprec.Handle,
				To:       a,
				ToName:   name,
				Rel:      edge.Relation,
			})
		}
	}

	return findings
}

func (r *ipnet) oneOfSources(e *et.Event, edge *dbt.Edge, src *et.Source, since time.Time) bool {
	if tags, err := e.Session.Cache().GetEdgeTags(edge, since, src.Name); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if _, ok := tag.Property.(*general.SourceProperty); ok {
				return true
			}
		}
	}
	return false
}

func (r *ipnet) store(e *et.Event, resp *rdap.IPNetwork, entity *dbt.Entity, m *config.Matches) {
	var findings []*support.Finding
	iprec := entity.Asset.(*oamreg.IPNetRecord)

	if u := r.plugin.getJSONLink(resp.Links); u != nil && m.IsMatch(string(oam.URL)) {
		if a, err := e.Session.Cache().CreateAsset(u); err == nil && a != nil {
			findings = append(findings, &support.Finding{
				From:     entity,
				FromName: "IPNetRecord: " + iprec.Handle,
				To:       a,
				ToName:   u.Raw,
				Rel:      &general.SimpleRelation{Name: "rdap_url"},
			})
		}
	}
	if name := iprec.WhoisServer; name != "" && m.IsMatch(string(oam.FQDN)) {
		fqdn := &oamdns.FQDN{Name: name}

		if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 {
			if a, err := e.Session.Cache().CreateAsset(fqdn); err == nil && a != nil {
				findings = append(findings, &support.Finding{
					From:     entity,
					FromName: "IPNetRecord: " + iprec.Handle,
					To:       a,
					ToName:   name,
					Rel:      &general.SimpleRelation{Name: "whois_server"},
				})
			}
		}
	}

	// process the relations built above
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)

	if m.IsMatch(string(oam.ContactRecord)) {
		for _, v := range resp.Entities {
			r.plugin.storeEntity(e, 1, &v, entity, r.plugin.source, m)
		}
	}
}

func (r *ipnet) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)
}
