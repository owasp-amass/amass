// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"errors"
	"time"

	"github.com/openrdap/rdap"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
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
	_, ok := e.Asset.Asset.(*oamreg.IPNetRecord)
	if !ok {
		return errors.New("failed to extract the IPNetRecord asset")
	}

	src := support.GetSource(e.Session, r.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	matches, err := e.Session.Config().CheckTransformations(
		string(oam.IPNetRecord), append(r.transforms, r.plugin.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

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

func (r *ipnet) lookup(e *et.Event, asset, src *dbt.Asset, m *config.Matches) []*support.Finding {
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
					Rel:      rel.Type,
				})
			}
		}
	})
	<-done
	close(done)
	return findings
}

func (r *ipnet) oneOfSources(e *et.Event, asset, src *dbt.Asset, since time.Time) bool {
	if rels, err := e.Session.DB().OutgoingRelations(asset, since, "source"); err == nil && len(rels) > 0 {
		for _, rel := range rels {
			if rel.ToAsset.ID == src.ID {
				return true
			}
		}
	}
	return false
}

func (r *ipnet) store(e *et.Event, resp *rdap.IPNetwork, asset, src *dbt.Asset, m *config.Matches) []*support.Finding {
	iprec := asset.Asset.(*oamreg.IPNetRecord)

	var findings []*support.Finding
	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		if u := r.plugin.getJSONLink(resp.Links); u != nil && m.IsMatch(string(oam.URL)) {
			if a, err := e.Session.DB().Create(asset, "rdap_url", u); err == nil && a != nil {
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: "IPNetRecord: " + iprec.Handle,
					To:       a,
					ToName:   u.Raw,
					Rel:      "rdap_url",
				})
				_, _ = e.Session.DB().Link(a, "source", src)
			}
		}
		if name := iprec.WhoisServer; name != "" && m.IsMatch(string(oam.FQDN)) {
			if a, err := e.Session.DB().Create(asset, "whois_server", &domain.FQDN{Name: name}); err == nil && a != nil {
				_, _ = e.Session.DB().Link(a, "source", src)

				if _, conf := e.Session.Scope().IsAssetInScope(a.Asset, 0); conf > 0 {
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "IPNetRecord: " + iprec.Handle,
						To:       a,
						ToName:   name,
						Rel:      "whois_server",
					})
				}
			}
		}
	})
	<-done
	close(done)

	if m.IsMatch(string(oam.ContactRecord)) {
		for _, entity := range resp.Entities {
			findings = append(findings, r.plugin.storeEntity(e, 1, &entity, asset, src, m)...)
		}
	}
	return findings
}

func (r *ipnet) process(e *et.Event, findings []*support.Finding, src *dbt.Asset) {
	support.ProcessAssetsWithSource(e, findings, src, r.plugin.name, r.name)
}
