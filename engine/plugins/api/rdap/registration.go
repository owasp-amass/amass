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
	"github.com/owasp-amass/open-asset-model/general"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// The RDAP query handlers (autonomous system, netblock and domain) share one
// flow: a registered asset is answered with its registration record, read
// from the database when the asset was looked up within the TTL and queried
// otherwise. The record is dispatched with the RDAP response, when there is
// one, so the record's detail handler stores the contacts and servers it
// carries.

// checkRegistration answers the event's asset with its registration record of
// recType, found again by the content filters within the TTL, or from query.
func (rd *rdapPlugin) checkRegistration(e *et.Event, handler string, recType oam.AssetType,
	filters dbt.ContentFilters, query func() (*dbt.Entity, any)) error {
	since, err := support.TTLStartTime(e.Session.Config(),
		string(e.Entity.Asset.AssetType()), string(recType), handler)
	if err != nil {
		return err
	}

	var record *dbt.Entity
	var resp any
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, rd.source, since) {
		record = rd.findRecord(e, recType, filters, since)
	} else {
		record, resp = query()
		support.MarkAssetMonitored(e.Session, e.Entity, rd.source)
	}

	if record != nil {
		name := recordName(record)
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    name,
			Meta:    resp,
			Entity:  record,
			Session: e.Session,
		})

		e.Session.Log().Info("relationship discovered", "from", e.Entity.Asset.Key(), "relation",
			"registration", "to", name, slog.Group("plugin", "name", rd.name, "handler", handler))
	}
	return nil
}

// findRecord returns the registration record of recType matching the
// filters that RDAP recorded since the time.
func (rd *rdapPlugin) findRecord(e *et.Event, recType oam.AssetType, filters dbt.ContentFilters, since time.Time) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	ents, err := e.Session.DB().FindEntitiesByContent(ctx, recType, since, 1, filters)
	if err != nil || len(ents) != 1 {
		return nil
	}

	if tags, err := e.Session.DB().FindEntityTags(ctx, ents[0], since, rd.source.Name); err == nil {
		for _, tag := range tags {
			if tag.Property.PropertyType() == oam.SourceProperty {
				return ents[0]
			}
		}
	}
	return nil
}

// storeRecord stores a registration record with RDAP as its source and links
// the registered asset to it.
func (rd *rdapPlugin) storeRecord(e *et.Event, registered *dbt.Entity, rec oam.Asset) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	record, err := e.Session.DB().CreateAsset(ctx, rec)
	if err != nil || record == nil {
		return nil
	}

	support.AddSource(ctx, e.Session, record, rd.source)

	_, _ = support.Relate(ctx, e.Session, registered, &general.SimpleRelation{Name: "registration"}, record, rd.source)
	return record
}

// registrationDates are the dates of an RDAP object's events, in the form the
// Open Asset Model records keep.
type registrationDates struct {
	created, changed, rdapUpdated, expiration string
}

func eventDates(events []rdap.Event) registrationDates {
	var d registrationDates
	for _, event := range events {
		t, err := time.Parse(time.RFC3339, event.Date)
		if err != nil {
			continue
		}

		switch strings.ToLower(event.Action) {
		case "registration":
			d.created = support.TimeToJSONString(&t)
		case "last changed":
			d.changed = support.TimeToJSONString(&t)
		case "last update of rdap database":
			d.rdapUpdated = support.TimeToJSONString(&t)
		case "expiration":
			d.expiration = support.TimeToJSONString(&t)
		}
	}
	return d
}

// recordName is how a registration record is named in events and findings.
func recordName(record *dbt.Entity) string {
	switch v := record.Asset.(type) {
	case *oamreg.AutnumRecord:
		return "AutnumRecord: " + v.Handle
	case *oamreg.IPNetRecord:
		return "IPNetRecord: " + v.Handle
	case *oamreg.DomainRecord:
		return "DomainRecord: " + v.Domain
	}
	return record.Asset.Key()
}
