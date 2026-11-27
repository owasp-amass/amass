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
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
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
	cands, err := queryByDomain(e.Session.Ctx(), e.Session.Clients().General, w.rlimit, domain)
	if err != nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", w.name, "handler", w.handler.name))
		return
	}
	// No match, or several entities claim this website: resolve none rather
	// than guess which company owns the domain (principle 8).
	if len(cands) != 1 || cands[0].BestName() == "" {
		return
	}
	w.store(e, domain, cands[0])
}

func (w *wikidata) store(e *et.Event, domain string, c company) {
	orgent := org.StoreDomainIdentity(e, domain, c.DomainIdentity, w.source)
	if orgent == nil {
		return
	}

	e.Session.Log().Info("organization identified from official website",
		"domain", domain, "org", orgent.Asset.(*oamorg.Organization).Name, "qid", c.QID,
		slog.Group("plugin", "name", w.name, "handler", w.handler.name))
}
