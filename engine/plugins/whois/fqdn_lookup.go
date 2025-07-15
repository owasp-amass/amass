// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	whoisclient "github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
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
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if dom, err := publicsuffix.EffectiveTLDPlusOne(domlt); err != nil || dom != domlt {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.DomainRecord), r.name)
	if err != nil {
		return err
	}

	var asset *dbt.Entity
	src := r.plugin.source
	var record *whoisparser.WhoisInfo
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		asset = r.lookup(e, fqdn.Name, src, since)
	} else {
		asset, record = r.query(e, fqdn.Name, e.Entity, src)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if asset != nil {
		r.process(e, record, e.Entity, asset)
		r.waitForDomRecContacts(e, asset)
	}
	return nil
}

func (r *fqdnLookup) lookup(e *et.Event, name string, src *et.Source, since time.Time) *dbt.Entity {
	if assets := support.SourceToAssetsWithinTTL(e.Session, name, string(oam.DomainRecord), src, since); len(assets) > 0 {
		return assets[0]
	}
	return nil
}

func (r *fqdnLookup) query(e *et.Event, name string, asset *dbt.Entity, src *et.Source) (*dbt.Entity, *whoisparser.WhoisInfo) {
	_ = r.plugin.rlimit.Wait(context.TODO())

	resp, err := whoisclient.Whois(name)
	if err != nil {
		return nil, nil
	}

	return r.store(e, resp, asset, src)
}

func (r *fqdnLookup) store(e *et.Event, resp string, asset *dbt.Entity, src *et.Source) (*dbt.Entity, *whoisparser.WhoisInfo) {
	fqdn := asset.Asset.(*oamdns.FQDN)

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

	autasset, err := e.Session.Cache().CreateAsset(dr)
	if err == nil && autasset != nil {
		if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   &general.SimpleRelation{Name: "registration"},
			FromEntity: asset,
			ToEntity:   autasset,
		}); err == nil && edge != nil {
			_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
		}
	}

	return autasset, &info
}

func (r *fqdnLookup) process(e *et.Event, record *whoisparser.WhoisInfo, fqdn, dr *dbt.Entity) {
	d := dr.Asset.(*oamreg.DomainRecord)

	name := d.Domain + " WHOIS domain record"
	_ = e.Dispatcher.DispatchEvent((&et.Event{
		Name:    name,
		Meta:    record,
		Entity:  dr,
		Session: e.Session,
	}))

	fname := fqdn.Asset.(*oamdns.FQDN)
	e.Session.Log().Info("relationship discovered", "from", fname.Name, "relation",
		"registration", "to", name, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
}

func (r *fqdnLookup) waitForDomRecContacts(e *et.Event, dr *dbt.Entity) {
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
		if edges, err := e.Session.Cache().OutgoingEdges(dr, e.Session.Cache().StartTime(), rtypes...); err == nil && len(edges) > 0 {
			return
		}
	}
}
