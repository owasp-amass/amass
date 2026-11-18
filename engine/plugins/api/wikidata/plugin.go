// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package wikidata identifies the organization behind a registered domain by
// reverse-looking-up Wikidata for the entity whose official website (P856) is
// that domain. It fills the gap left for cloud-hosted companies, whose netblock
// registrant, DV certificate and redacted WHOIS name only their hosts, not the
// company: no Organization is created for the company itself, so nothing
// downstream (geography, funding, country inference, GLEIF enrichment) has
// anything to attach to.
//
// On a DomainRecord it queries Wikidata by the domain and, when exactly one
// entity claims that official website (several is ambiguous and resolves none,
// per principle 8), creates the Organization and attaches it to the domain with
// the existing OAM chain Organization --website--> URL --domain--> FQDN. The
// entity's official name (P1448), country (P17 -> ISO alpha-2 via P297) and LEI
// (P1278) are stored; the LEI hands GLEIF an exact key for authoritative
// enrichment. Keyless, rate-limited, TTL-cadenced. Every asset and edge it
// creates carries a Wikidata SourceProperty.
package wikidata

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"golang.org/x/time/rate"
)

type wikidata struct {
	name    string
	log     *slog.Logger
	rlimit  *rate.Limiter
	source  *et.Source
	handler *handler
	website *websiteHandler
}

type handler struct {
	name   string
	plugin *wikidata
}

// NewWikidata returns the Wikidata organization-identity collector.
func NewWikidata() et.Plugin {
	return &wikidata{
		name:   "Wikidata",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		// Curated and keyed on the exact official website, but third-party
		// asserted, so high but not registry-authoritative confidence.
		source: &et.Source{Name: "Wikidata", Confidence: 85},
	}
}

func (w *wikidata) Name() string { return w.name }

func (w *wikidata) Start(r et.Registry) error {
	w.log = r.Log().WithGroup("plugin").With("name", w.name)

	w.handler = &handler{name: w.name + "-Domain-Handler", plugin: w}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       w,
		Name:         w.handler.name,
		Position:     50,
		Exclusive:    false,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.Organization),
			string(oam.URL),
			string(oam.FQDN),
			string(oam.Identifier),
		},
		EventType: oam.DomainRecord,
		Callback:  w.handler.check,
	}); err != nil {
		return err
	}

	// Forward direction: an in-scope Organization -> its official-website domains.
	w.website = &websiteHandler{name: w.name + "-Website-Handler", plugin: w}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       w,
		Name:         w.website.name,
		Position:     50,
		Exclusive:    false,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.URL), string(oam.FQDN)},
		EventType:    oam.Organization,
		Callback:     w.website.check,
	}); err != nil {
		return err
	}

	w.log.Info("Plugin started")
	return nil
}

func (w *wikidata) Stop() { w.log.Info("Plugin stopped") }

func (h *handler) check(e *et.Event) error {
	dr, ok := e.Entity.Asset.(*oamreg.DomainRecord)
	if !ok {
		return nil
	}
	domain := strings.ToLower(strings.TrimSpace(dr.Domain))
	if domain == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.DomainRecord), string(oam.Organization), h.plugin.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, h.plugin.source, since) {
		return nil
	}

	h.plugin.query(e, domain)
	support.MarkAssetMonitored(e.Session, e.Entity, h.plugin.source)
	return nil
}

func (w *wikidata) query(e *et.Event, domain string) {
	cands, err := queryByDomain(e.Session.Ctx(), w.rlimit, domain)
	if err != nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", w.name, "handler", w.handler.name))
		return
	}
	// No match, or several entities claim this website: resolve none rather
	// than guess which company owns the domain (principle 8).
	if len(cands) != 1 || cands[0].bestName() == "" {
		return
	}
	w.store(e, domain, cands[0])
}

func (w *wikidata) store(e *et.Event, domain string, c company) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	// Reuse an organization another identity source already created for this
	// domain rather than making a duplicate; only create (and build the website
	// chain) when none exists.
	orgent := org.OrgForControlledDomain(e.Session, domain)
	if orgent == nil {
		var err error
		orgent, err = org.CreateOrgAsset(e.Session, nil, nil, &oamorg.Organization{
			Name:         c.bestName(),
			LegalName:    c.LegalName,
			Jurisdiction: c.Country,
		}, w.source)
		if err != nil || orgent == nil {
			return
		}

		// Organization --website--> URL --domain--> apex FQDN (existing OAM chain).
		if u := support.RawURLToOAM(c.Website); u != nil {
			if urlent, err := e.Session.DB().CreateAsset(ctx, u); err == nil && urlent != nil {
				w.sourceProp(ctx, e, urlent)
				_ = w.createRelation(ctx, e.Session, orgent, &oamgen.SimpleRelation{Name: "website"}, urlent)

				if fq, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: domain}); err == nil && fq != nil {
					w.sourceProp(ctx, e, fq)
					_ = w.createRelation(ctx, e.Session, urlent, &oamgen.SimpleRelation{Name: "domain"}, fq)
				}
			}
		}
	} else {
		// Reusing another source's org: add Wikidata provenance, and fill the
		// jurisdiction when it is still unset.
		w.sourceProp(ctx, e, orgent)
		if o := orgent.Asset.(*oamorg.Organization); c.Country != "" && o.Jurisdiction == "" {
			o.Jurisdiction = c.Country
			_, _ = e.Session.DB().CreateEntity(ctx, orgent)
		}
	}

	// The LEI identifier is an exact key GLEIF's handlers enrich from.
	if c.LEI != "" {
		id := &oamgen.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", oamgen.LEICode, c.LEI),
			ID:       c.LEI,
			Type:     oamgen.LEICode,
		}
		if ident, err := e.Session.DB().CreateAsset(ctx, id); err == nil && ident != nil {
			w.sourceProp(ctx, e, ident)
			_ = w.createRelation(ctx, e.Session, orgent, &oamgen.SimpleRelation{Name: "id"}, ident)
			_ = e.Dispatcher.DispatchEvent(&et.Event{Name: id.UniqueID, Entity: ident, Session: e.Session})
		}
	}

	o := orgent.Asset.(*oamorg.Organization)
	_ = e.Dispatcher.DispatchEvent(&et.Event{Name: fmt.Sprintf("%s:%s", o.Name, o.ID), Entity: orgent, Session: e.Session})
	e.Session.Log().Info("organization identified from official website",
		"domain", domain, "org", o.Name, "qid", c.QID,
		slog.Group("plugin", "name", w.name, "handler", w.handler.name))
}

func (w *wikidata) sourceProp(ctx context.Context, e *et.Event, ent *dbt.Entity) {
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &oamgen.SourceProperty{
		Source:     w.source.Name,
		Confidence: w.source.Confidence,
	})
}

func (w *wikidata) createRelation(ctx context.Context, sess et.Session, obj *dbt.Entity,
	rel oam.Relation, subject *dbt.Entity) error {
	edge, err := sess.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: obj, ToEntity: subject})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}
	_, err = sess.DB().CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
		Source:     w.source.Name,
		Confidence: w.source.Confidence,
	})
	return err
}
