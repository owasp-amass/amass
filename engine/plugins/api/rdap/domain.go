// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"golang.org/x/net/publicsuffix"
)

// domain is the RDAP discovery handler: it turns a registered domain name
// into the DomainRecord the registry's RDAP server serves. RDAP returns the
// registration as structured JSON, so the record and its contacts are read
// without the per-registrar free-text parsing the WHOIS plugin relies on.
type domain struct {
	name   string
	plugin *rdapPlugin
}

func (d *domain) Name() string {
	return d.name
}

func (d *domain) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return nil
	}

	// Only a registered domain (an apex) has a domain record; a name below
	// one does not, the same gate the WHOIS plugin applies.
	name := strings.ToLower(fqdn.Name)
	if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err != nil || dom != name {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.FQDN), string(oam.DomainRecord), d.name)
	if err != nil {
		return err
	}

	var asset *dbt.Entity
	var record *rdap.Domain
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, d.plugin.source, since) {
		asset = d.lookup(e, name, since)
	} else {
		asset, record = d.query(e, name, e.Entity)
		support.MarkAssetMonitored(e.Session, e.Entity, d.plugin.source)
	}

	if asset != nil {
		d.process(e, record, asset)
	}
	return nil
}

func (d *domain) lookup(e *et.Event, name string, since time.Time) *dbt.Entity {
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
		since, d.plugin.source.Name); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if tag.Property.PropertyType() == oam.SourceProperty {
				return dr
			}
		}
	}
	return nil
}

func (d *domain) query(e *et.Event, name string, asset *dbt.Entity) (*dbt.Entity, *rdap.Domain) {
	_ = support.WaitLimit(e.Session.Ctx(), d.plugin.rlimit)

	record, err := d.plugin.client.QueryDomain(name)
	if err != nil || record == nil {
		return nil, nil
	}
	return d.store(e, record, asset), record
}

// store builds the DomainRecord from the RDAP response and links the domain
// name to it. The domain's registration dates come from the response's
// events, its DNSSEC flag from the secure-DNS object, and its WHOIS server
// from the port-43 referral.
func (d *domain) store(e *et.Event, resp *rdap.Domain, asset *dbt.Entity) *dbt.Entity {
	fqdn, ok := asset.Asset.(*oamdns.FQDN)
	if !ok {
		return nil
	}

	name := strings.ToLower(fqdn.Name)
	dr := &oamreg.DomainRecord{
		ID:          resp.Handle,
		Domain:      name,
		WhoisServer: strings.ToLower(resp.Port43),
		Status:      resp.Status,
		DNSSEC:      secureDNSSigned(resp.SecureDNS),
	}
	if ldh := strings.ToLower(resp.LDHName); ldh != "" && ldh != name {
		dr.Punycode = ldh
	}
	if resp.UnicodeName != "" {
		dr.Name = resp.UnicodeName
	}
	if _, ext, found := strings.Cut(name, "."); found {
		dr.Extension = ext
	}

	for _, event := range resp.Events {
		t, err := time.Parse(time.RFC3339, event.Date)
		if err != nil {
			continue
		}

		switch strings.ToLower(event.Action) {
		case "registration":
			dr.CreatedDate = support.TimeToJSONString(&t)
		case "last changed", "last update of rdap database":
			dr.UpdatedDate = support.TimeToJSONString(&t)
		case "expiration":
			dr.ExpirationDate = support.TimeToJSONString(&t)
		}
	}

	// A record with neither an identifier nor a registration date carries no
	// more than the name already known, so it is not stored.
	if dr.ID == "" && dr.CreatedDate == "" && len(dr.Status) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	record, err := e.Session.DB().CreateAsset(ctx, dr)
	if err != nil || record == nil {
		return nil
	}

	_, _ = e.Session.DB().CreateEntityProperty(ctx, record, &general.SourceProperty{
		Source:     d.plugin.source.Name,
		Confidence: d.plugin.source.Confidence,
	})

	if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "registration"},
		FromEntity: asset,
		ToEntity:   record,
	}); err == nil && edge != nil {
		_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
			Source:     d.plugin.source.Name,
			Confidence: d.plugin.source.Confidence,
		})
	}
	return record
}

func (d *domain) process(e *et.Event, record *rdap.Domain, asset *dbt.Entity) {
	dr := asset.Asset.(*oamreg.DomainRecord)

	name := "DomainRecord: " + dr.Domain
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    name,
		Meta:    record,
		Entity:  asset,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", dr.Domain, "relation",
		"registration", "to", name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
}

// secureDNSSigned reports whether the RDAP secure-DNS object says the zone is
// DNSSEC-signed: the delegation-signed flag when the server sets it, and
// otherwise the presence of a DS or key record.
func secureDNSSigned(s *rdap.SecureDNS) bool {
	if s == nil {
		return false
	}
	if s.DelegationSigned != nil {
		return *s.DelegationSigned
	}
	return len(s.DS) > 0 || len(s.Keys) > 0
}
