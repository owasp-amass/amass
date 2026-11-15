// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package lookalike finds, during enumeration, the registered domains
// one typing mistake away from each in-scope registered domain that DNS
// delegates, and stores them with their name servers and mail servers. Which
// ones are the subject's own and which are not is left to the lookalike lens.
package lookalike

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/lookalike"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/resolve/utils"
)

type lookalikes struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

// NewLookalikes returns the lookalike domain collection plugin.
func NewLookalikes() et.Plugin {
	return &lookalikes{name: "Lookalike-Domains", source: &et.Source{Name: "Lookalike-Domains", Confidence: 100}}
}

func (l *lookalikes) Name() string {
	return l.name
}

func (l *lookalikes) Start(r et.Registry) error {
	l.log = r.Log().WithGroup("plugin").With("name", l.name)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       l,
		Name:         l.name + "-Handler",
		Position:     14,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     l.check,
	}); err != nil {
		return err
	}

	l.log.Info("Plugin started")
	return nil
}

func (l *lookalikes) Stop() {
	l.log.Info("Plugin stopped")
}

// check looks for lookalikes of an in-scope registered domain, once within
// its time to live.
func (l *lookalikes) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	cfg := e.Session.Config()
	if cfg == nil {
		return nil
	}

	name := strings.ToLower(strings.TrimSuffix(fqdn.Name, "."))
	if _, _, ok := lookalike.Split(name); !ok {
		return nil // not a registered domain
	}
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf <= 0 {
		return nil
	}

	since, err := support.TTLStartTime(cfg, "FQDN", "FQDN", l.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, l.source, since) {
		return nil
	}

	rules, err := lookalike.LoadRules()
	if err != nil {
		return err
	}

	found := 0
	for _, c := range rules.Candidates(name) {
		if e.Session.Done() {
			break
		}
		if l.store(e, c) {
			found++
		}
	}

	support.MarkAssetMonitored(e.Session, e.Entity, l.source)
	if found > 0 {
		e.Session.Log().Info("lookalike domains found", "domain", name, "count", found,
			slog.Group("plugin", "name", l.name, "handler", l.name+"-Handler"))
	}

	return nil
}

// store keeps a candidate that DNS delegates, with its name servers and
// mail servers, and reports whether it did.
func (l *lookalikes) store(e *et.Event, name string) bool {
	ns, err := support.PerformQuery(e.Session.Ctx(), name, dns.TypeNS)
	if err != nil || !hasType(ns, dns.TypeNS) {
		return false
	}

	mx, _ := support.PerformQuery(e.Session.Ctx(), name, dns.TypeMX)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	db := e.Session.DB()
	ent, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: name})
	if err != nil || ent == nil {
		return false
	}

	_, _ = db.CreateEntityProperty(ctx, ent, &oamgen.SourceProperty{Source: l.source.Name,
		Confidence: l.source.Confidence})

	for _, rr := range append(ns, mx...) {
		var target string
		var rel oam.Relation
		header := oamdns.RRHeader{RRType: int(rr.Header().Rrtype), Class: int(rr.Header().Class),
			TTL: int(rr.Header().Ttl)}
		switch r := rr.(type) {
		case *dns.NS:
			target = utils.RemoveLastDot(r.Ns)
			rel = &oamdns.BasicDNSRelation{Name: "dns_record", Header: header}
		case *dns.MX:
			target = utils.RemoveLastDot(r.Mx)
			rel = &oamdns.PrefDNSRelation{Name: "dns_record", Header: header, Preference: int(r.Preference)}
		default:
			continue
		}
		if target == "" {
			continue // a null MX (RFC 7505) names no host
		}

		to, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: target})
		if err != nil || to == nil {
			continue
		}
		if edge, err := db.CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: ent, ToEntity: to}); err == nil {
			_, _ = db.CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{Source: l.source.Name,
				Confidence: l.source.Confidence})
		}
	}

	return true
}

func hasType(rr []dns.RR, t uint16) bool {
	for _, r := range rr {
		if r.Header().Rrtype == t {
			return true
		}
	}

	return false
}
