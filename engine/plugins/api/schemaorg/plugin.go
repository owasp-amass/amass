// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package schemaorg identifies the organization behind a registered domain from
// the schema.org Organization markup a site publishes about itself on its
// homepage (JSON-LD). It is the lowest-confidence org-identity source and a
// corroborator/bootstrapper: self-asserted markup is unverified, often absent
// or thin, and sometimes names an agency or parent, so it creates an
// organization at low confidence. Its real value is the exact keys it carries —
// a leiCode hands GLEIF an authoritative lookup, turning a weak self-assertion
// into a high-confidence record.
//
// Fetching the homepage contacts the target, so it runs only in active mode. On
// a DomainRecord it fetches the apex homepage, parses the schema.org
// Organization (name, legalName, address country, leiCode) and, when one names
// itself, creates the Organization and attaches it with the OAM chain
// Organization --website--> URL --domain--> FQDN. Keyless, rate-limited,
// TTL-cadenced; every asset and edge carries a SchemaOrg SourceProperty.
package schemaorg

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

type schemaorg struct {
	name    string
	log     *slog.Logger
	rlimit  *rate.Limiter
	source  *et.Source
	handler *handler
}

type handler struct {
	name   string
	plugin *schemaorg
}

// NewSchemaOrg returns the homepage schema.org organization-identity collector.
func NewSchemaOrg() et.Plugin {
	return &schemaorg{
		name:   "SchemaOrg",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		// Self-asserted and unverified: low standalone confidence. Its value is
		// corroboration and the exact keys (leiCode) it bootstraps from.
		source: &et.Source{Name: "SchemaOrg", Confidence: 50},
	}
}

func (s *schemaorg) Name() string { return s.name }

func (s *schemaorg) Start(r et.Registry) error {
	s.log = r.Log().WithGroup("plugin").With("name", s.name)

	s.handler = &handler{name: s.name + "-Homepage-Handler", plugin: s}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       s,
		Name:         s.handler.name,
		Position:     51,
		Exclusive:    false,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.Organization),
			string(oam.URL),
			string(oam.FQDN),
			string(oam.Identifier),
		},
		EventType: oam.DomainRecord,
		Callback:  s.handler.check,
	}); err != nil {
		return err
	}

	s.log.Info("Plugin started")
	return nil
}

func (s *schemaorg) Stop() { s.log.Info("Plugin stopped") }

func (h *handler) check(e *et.Event) error {
	dr, ok := e.Entity.Asset.(*oamreg.DomainRecord)
	if !ok {
		return nil
	}
	// Fetching the homepage contacts the target: active mode only.
	if !e.Session.Config().Active {
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

func (s *schemaorg) query(e *et.Event, domain string) {
	html := fetchHomepage(e.Session.Ctx(), e.Session.Clients().Crawl, s.rlimit, domain)
	if html == "" {
		return
	}
	c, ok := parseSchemaOrg([]byte(html))
	if !ok || c.BestName() == "" {
		return
	}
	s.store(e, domain, c)
}

func (s *schemaorg) store(e *et.Event, domain string, c company) {
	orgent := org.StoreDomainIdentity(e, domain, c, s.source)
	if orgent == nil {
		return
	}

	e.Session.Log().Info("organization identified from homepage schema.org markup",
		"domain", domain, "org", orgent.Asset.(*oamorg.Organization).Name,
		slog.Group("plugin", "name", s.name, "handler", s.handler.name))
}
