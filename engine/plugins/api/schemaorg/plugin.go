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
	html := fetchHomepage(e.Session.Ctx(), s.rlimit, domain)
	if html == "" {
		return
	}
	c, ok := parseSchemaOrg([]byte(html))
	if !ok || c.bestName() == "" {
		return
	}
	s.store(e, domain, c)
}

func (s *schemaorg) store(e *et.Event, domain string, c company) {
	orgent, err := org.CreateOrgAsset(e.Session, nil, nil, &oamorg.Organization{
		Name:         c.bestName(),
		LegalName:    c.LegalName,
		Jurisdiction: c.Country,
	}, s.source)
	if err != nil || orgent == nil {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	// Organization --website--> URL --domain--> apex FQDN (existing OAM chain).
	if u := support.RawURLToOAM("https://" + domain); u != nil {
		if urlent, err := e.Session.DB().CreateAsset(ctx, u); err == nil && urlent != nil {
			s.sourceProp(ctx, e, urlent)
			_ = s.createRelation(ctx, e.Session, orgent, &oamgen.SimpleRelation{Name: "website"}, urlent)

			if fq, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: domain}); err == nil && fq != nil {
				s.sourceProp(ctx, e, fq)
				_ = s.createRelation(ctx, e.Session, urlent, &oamgen.SimpleRelation{Name: "domain"}, fq)
			}
		}
	}

	// A leiCode is an exact key GLEIF's handlers enrich from authoritatively,
	// turning this low-confidence self-assertion into a high-confidence record.
	if c.LEI != "" {
		id := &oamgen.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", oamgen.LEICode, c.LEI),
			ID:       c.LEI,
			Type:     oamgen.LEICode,
		}
		if ident, err := e.Session.DB().CreateAsset(ctx, id); err == nil && ident != nil {
			s.sourceProp(ctx, e, ident)
			_ = s.createRelation(ctx, e.Session, orgent, &oamgen.SimpleRelation{Name: "id"}, ident)
			_ = e.Dispatcher.DispatchEvent(&et.Event{Name: id.UniqueID, Entity: ident, Session: e.Session})
		}
	}

	o := orgent.Asset.(*oamorg.Organization)
	_ = e.Dispatcher.DispatchEvent(&et.Event{Name: fmt.Sprintf("%s:%s", o.Name, o.ID), Entity: orgent, Session: e.Session})
	e.Session.Log().Info("organization identified from homepage schema.org markup",
		"domain", domain, "org", o.Name,
		slog.Group("plugin", "name", s.name, "handler", s.handler.name))
}

func (s *schemaorg) sourceProp(ctx context.Context, e *et.Event, ent *dbt.Entity) {
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &oamgen.SourceProperty{
		Source:     s.source.Name,
		Confidence: s.source.Confidence,
	})
}

func (s *schemaorg) createRelation(ctx context.Context, sess et.Session, obj *dbt.Entity,
	rel oam.Relation, subject *dbt.Entity) error {
	edge, err := sess.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: obj, ToEntity: subject})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}
	_, err = sess.DB().CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
		Source:     s.source.Name,
		Confidence: s.source.Confidence,
	})
	return err
}
