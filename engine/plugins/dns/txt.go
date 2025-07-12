// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

type dnsTXT struct {
	name   string
	plugin *dnsPlugin
	source *et.Source
}

func (d *dnsTXT) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", d.plugin.name)
	if err != nil {
		return err
	}

	var txtRecords []dns.RR
	var props []*oamdns.DNSRecordProperty
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, d.source, since) {
		props = d.lookup(e, e.Entity, since)
	} else {
		txtRecords = d.query(e, e.Entity)
		d.store(e, e.Entity, txtRecords)
	}

	if len(txtRecords) > 0 {
		d.process(e, e.Entity, txtRecords, props)
		support.AddDNSRecordType(e, int(dns.TypeTXT))
	}
	return nil
}

func (d *dnsTXT) lookup(e *et.Event, fqdn *dbt.Entity, since time.Time) []*oamdns.DNSRecordProperty {
	var props []*oamdns.DNSRecordProperty

	n, ok := fqdn.Asset.(*oamdns.FQDN)
	if !ok || n == nil {
		return props
	}

	if tags, err := e.Session.Cache().GetEntityTags(fqdn, since, "dns_record"); err == nil {
		for _, tag := range tags {
			if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
				props = append(props, prop)
			}
		}
	}

	return props
}

func (d *dnsTXT) query(e *et.Event, name *dbt.Entity) []dns.RR {
	var txtRecords []dns.RR

	fqdn, ok := name.Asset.(*oamdns.FQDN)
	if !ok {
		return txtRecords
	}

	if rr, err := support.PerformQuery(fqdn.Name, dns.TypeTXT); err == nil {
		txtRecords = append(txtRecords, rr...)
		support.MarkAssetMonitored(e.Session, name, d.source)
	}

	return txtRecords
}

func (d *dnsTXT) store(e *et.Event, fqdn *dbt.Entity, rr []dns.RR) {
	for _, record := range rr {
		if record.Header().Rrtype != dns.TypeTXT {
			continue
		}

		txtValue := strings.Join((record.(*dns.TXT)).Txt, " ")
		_, err := e.Session.Cache().CreateEntityProperty(fqdn, &oamdns.DNSRecordProperty{
			PropertyName: "dns_record",
			Header: oamdns.RRHeader{
				RRType: int(dns.TypeTXT),
				Class:  int(record.Header().Class),
				TTL:    int(record.Header().Ttl),
			},
			Data: txtValue,
		})
		if err != nil {
			msg := fmt.Sprintf("failed to create entity property for %s: %s", txtValue, err)
			e.Session.Log().Error(msg, "error", err.Error(),
				slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}
}

func (d *dnsTXT) process(e *et.Event, fqdn *dbt.Entity, txtRecords []dns.RR, props []*oamdns.DNSRecordProperty) {
	for _, record := range txtRecords {
		e.Session.Log().Info("TXT record discovered", "fqdn", fqdn.Asset.(*oamdns.FQDN).Name,
			"txt", strings.Join((record.(*dns.TXT)).Txt, " "), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
	for _, prop := range props {
		e.Session.Log().Info("TXT record discovered", "fqdn", fqdn.Asset.(*oamdns.FQDN).Name,
			"txt", prop.Data, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}
