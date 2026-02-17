// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"context"
	"errors"
	"fmt"
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
		return errors.New("failed to cast the FQDN asset")
	}

	name := strings.ToLower(fqdn.Name)
	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err != nil || dom != name {
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
		asset = r.lookup(e, fqdn.Name, since)
	} else {
		asset, record = r.query(e, fqdn.Name, e.Entity, src)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if asset != nil {
		r.process(e, record, e.Entity, asset)
	}
	return nil
}

func (r *fqdnLookup) lookup(e *et.Event, name string, since time.Time) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	ents, err := e.Session.DB().FindEntitiesByContent(ctx, oam.DomainRecord, since, 1, dbt.ContentFilters{
		"domain": name,
	})
	if err != nil || len(ents) != 1 {
		return nil
	}
	dr := ents[0]

	if tags, err := e.Session.DB().FindEntityTags(ctx, dr,
		since, r.plugin.source.Name); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if tag.Property.PropertyType() == oam.SourceProperty {
				return dr
			}
		}
	}

	return nil
}

func (r *fqdnLookup) query(e *et.Event, name string, fent *dbt.Entity, src *et.Source) (*dbt.Entity, *whoisparser.WhoisInfo) {
	_ = r.plugin.rlimit.Wait(e.Session.Ctx())

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	var resp string
	ch := make(chan string, 1)
	go r.whoisRoutine(e.Session, name, ch)

	select {
	case <-ctx.Done():
		return nil, nil
	case resp = <-ch:
	}

	return r.store(e, resp, fent, src)
}

func (r *fqdnLookup) whoisRoutine(sess et.Session, name string, ch chan string) {
	resp, err := whoisclient.Whois(name)
	if err != nil {
		msg := fmt.Sprintf("failed to acquire the WHOIS record for %s", name)
		sess.Log().Error(msg, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
		ch <- ""
		return
	}

	ch <- resp
}

func (r *fqdnLookup) store(e *et.Event, resp string, fent *dbt.Entity, src *et.Source) (*dbt.Entity, *whoisparser.WhoisInfo) {
	fqdn := fent.Asset.(*oamdns.FQDN)

	info, err := whoisparser.Parse(resp)
	if err != nil || !strings.EqualFold(info.Domain.Domain, fqdn.Name) {
		msg := fmt.Sprintf("failed to parse the WHOIS record for %s", fqdn.Name)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
		return nil, nil
	}

	dr := &oamreg.DomainRecord{
		Raw:            resp,
		ID:             info.Domain.ID,
		Domain:         strings.ToLower(info.Domain.Domain),
		Punycode:       info.Domain.Punycode,
		Name:           info.Domain.Name,
		Extension:      info.Domain.Extension,
		WhoisServer:    strings.ToLower(info.Domain.WhoisServer),
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

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	autasset, err := e.Session.DB().CreateAsset(ctx, dr)
	if err == nil && autasset != nil {
		if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
			Relation:   &general.SimpleRelation{Name: "registration"},
			FromEntity: fent,
			ToEntity:   autasset,
		}); err == nil && edge != nil {
			_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
			msg := fmt.Sprintf("successfully acquired the WHOIS record for %s", fqdn.Name)
			e.Session.Log().Info(msg, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
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
