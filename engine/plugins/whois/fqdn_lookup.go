// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	whoisclient "github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"golang.org/x/net/publicsuffix"
)

type fqdnLookup struct {
	name   string
	plugin *whois
}

func (r *fqdnLookup) Name() string {
	return r.name
}

func (r *fqdnLookup) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if dom, err := publicsuffix.EffectiveTLDPlusOne(domlt); err != nil || dom != domlt {
		return nil
	}

	src := support.GetSource(e.Session, r.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.DomainRecord), r.name)
	if err != nil {
		return err
	}

	var asset *dbt.Asset
	var record *whoisparser.WhoisInfo
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		asset = r.lookup(e, fqdn.Name, src, since)
	} else {
		asset, record = r.query(e, fqdn.Name, e.Asset, src)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if asset != nil {
		r.process(e, record, e.Asset, asset, src)
		r.waitForDomRecContacts(e, asset)
	}
	return nil
}

func (r *fqdnLookup) lookup(e *et.Event, name string, src *dbt.Asset, since time.Time) *dbt.Asset {
	if assets := support.SourceToAssetsWithinTTL(e.Session, name, string(oam.DomainRecord), src, since); len(assets) > 0 {
		return assets[0]
	}
	return nil
}

func (r *fqdnLookup) query(e *et.Event, name string, asset, src *dbt.Asset) (*dbt.Asset, *whoisparser.WhoisInfo) {
	r.plugin.rlimit.Take()
	resp, err := whoisclient.Whois(name)
	if err != nil {
		return nil, nil
	}

	return r.store(e, resp, asset, src)
}

func (r *fqdnLookup) store(e *et.Event, resp string, asset, src *dbt.Asset) (*dbt.Asset, *whoisparser.WhoisInfo) {
	fqdn := asset.Asset.(*domain.FQDN)

	info, err := whoisparser.Parse(resp)
	if err != nil || info.Domain.Domain != fqdn.Name {
		return nil, nil
	}

	dr := &oamreg.DomainRecord{
		Raw:            resp,
		ID:             info.Domain.ID,
		Domain:         info.Domain.Domain,
		Punycode:       info.Domain.Punycode,
		Name:           info.Domain.Name,
		Extension:      info.Domain.Extension,
		WhoisServer:    info.Domain.WhoisServer,
		CreatedDate:    info.Domain.CreatedDate,
		UpdatedDate:    info.Domain.UpdatedDate,
		ExpirationDate: info.Domain.ExpirationDate,
		DNSSEC:         info.Domain.DNSSec,
	}

	dr.Status = append(dr.Status, info.Domain.Status...)
	if tstr := support.TimeToJSONString(info.Domain.CreatedDateInTime); tstr != "" {
		dr.CreatedDate = tstr
	}
	if tstr := support.TimeToJSONString(info.Domain.UpdatedDateInTime); tstr != "" {
		dr.UpdatedDate = tstr
	}
	if tstr := support.TimeToJSONString(info.Domain.ExpirationDateInTime); tstr != "" {
		dr.ExpirationDate = tstr
	}

	done := make(chan *dbt.Asset, 1)
	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		if a, err := e.Session.DB().Create(asset, "registration", dr); err == nil && a != nil {
			_, _ = e.Session.DB().Link(a, "source", src)
			done <- a
			return
		}
		done <- nil
	})
	autasset := <-done
	close(done)
	return autasset, &info
}

func (r *fqdnLookup) process(e *et.Event, record *whoisparser.WhoisInfo, fqdn, dr, src *dbt.Asset) {
	d := dr.Asset.(*oamreg.DomainRecord)

	name := d.Domain + " WHOIS domain record"
	_ = e.Dispatcher.DispatchEvent((&et.Event{
		Name:    name,
		Meta:    record,
		Asset:   dr,
		Session: e.Session,
	}))

	now := time.Now()
	if to, hit := e.Session.Cache().GetAsset(dr.Asset); hit && to != nil {
		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "registration",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: fqdn,
			ToAsset:   to,
		})
		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "source",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: to,
			ToAsset:   src,
		})

		fname := fqdn.Asset.(*domain.FQDN)
		e.Session.Log().Info("relationship discovered", "from",
			fname.Name, "relation", "registration", "to", name,
			slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
	}
}

func (r *fqdnLookup) waitForDomRecContacts(e *et.Event, dr *dbt.Asset) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	tick := time.NewTicker(10 * time.Second)
	defer t.Stop()

	for range tick.C {
		select {
		case <-t.C:
			// stop after one minute of waiting
			return
		default:
		}

		rtypes := []string{"registrant_contact", "admin_contact", "technical_contact", "billing_contact"}
		for _, rtype := range rtypes {
			if relations, hit := e.Session.Cache().GetRelations(&dbt.Relation{
				Type:      rtype,
				FromAsset: dr,
			}); hit && len(relations) > 0 {
				return
			}
		}
	}
}
