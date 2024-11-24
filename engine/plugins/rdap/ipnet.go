// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"errors"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/property"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/relation"
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

	src := r.plugin.source
	var findings []*support.Finding
	if record, ok := e.Meta.(*rdap.IPNetwork); ok && record != nil {
		findings = append(findings, r.store(e, record, e.Asset, src, matches)...)
	} else {
		findings = append(findings, r.lookup(e, e.Asset, src, matches)...)
	}

	if len(findings) > 0 {
		r.process(e, findings, src)
	}
	return nil
}

func (r *ipnet) lookup(e *et.Event, asset *dbt.Entity, src *et.Source, m *config.Matches) []*support.Finding {
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

			if !r.oneOfSources(e, edge, src, since) {
				continue
			}

			var name string
			switch v := a.Asset.(type) {
			case *domain.FQDN:
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
			if _, ok := tag.Property.(*property.SourceProperty); ok {
				return true
			}
		}
	}
	return false
}

func (r *ipnet) store(e *et.Event, resp *rdap.IPNetwork, asset *dbt.Entity, src *et.Source, m *config.Matches) []*support.Finding {
	var findings []*support.Finding
	iprec := asset.Asset.(*oamreg.IPNetRecord)

	if u := r.plugin.getJSONLink(resp.Links); u != nil && m.IsMatch(string(oam.URL)) {
		if a, err := e.Session.Cache().CreateAsset(u); err == nil && a != nil {
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "IPNetRecord: " + iprec.Handle,
				To:       a,
				ToName:   u.Raw,
				Rel:      &relation.SimpleRelation{Name: "rdap_url"},
			})
		}
	}
	if name := iprec.WhoisServer; name != "" && m.IsMatch(string(oam.FQDN)) {
		if a, err := e.Session.Cache().CreateAsset(&domain.FQDN{Name: name}); err == nil && a != nil {
			if _, conf := e.Session.Scope().IsAssetInScope(a.Asset, 0); conf > 0 {
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: "IPNetRecord: " + iprec.Handle,
					To:       a,
					ToName:   name,
					Rel:      &relation.SimpleRelation{Name: "whois_server"},
				})
			}
		}
	}

	if m.IsMatch(string(oam.ContactRecord)) {
		for _, entity := range resp.Entities {
			findings = append(findings, r.plugin.storeEntity(e, 1, &entity, asset, src, m)...)
		}
	}

	return findings
}

func (r *ipnet) process(e *et.Event, findings []*support.Finding, src *et.Source) {
	support.ProcessAssetsWithSource(e, findings, src, r.plugin.name, r.name)
}
