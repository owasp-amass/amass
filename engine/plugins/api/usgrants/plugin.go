// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package usgrants collects United States federal research grants made to an
// enumerated Organization from three keyless public APIs — NSF Award Search,
// NIH RePORTER and SBIR/STTR — and stores each as a FundsTransfer the funding
// lens surfaces, with the funding agency as the funding party. These complement
// the USAspending collector (contracts/assistance) with research-grant funding.
//
// All three are keyless and run by default, no setup required; each applies only
// to US recipients (a non-US organization matches nothing). Recipients are
// matched to the subject by normalized name to guard against same-name entities,
// requests are rate-limited, and collection follows the TTL cadence. One plugin
// hosts the three as separate handlers so each has its own source and TTL.
package usgrants

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

type usgrants struct {
	name   string
	rlimit *rate.Limiter
	log    *slog.Logger
	srcs   []*source
}

// source is one of the three grant APIs: its handler name, the et.Source used
// for tagging and TTL, and the per-organization query callback.
type source struct {
	plugin *usgrants
	name   string
	src    *et.Source
	run    func(h *source, e *et.Event, orgent *dbt.Entity, name string)
}

// NewUSGrants returns the NSF/NIH/SBIR federal research-grant collector.
func NewUSGrants() et.Plugin {
	p := &usgrants{
		name:   "USGrants",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
	}
	p.srcs = []*source{
		{plugin: p, name: "NSF", src: &et.Source{Name: "NSF", Confidence: 80}, run: queryNSF},
		{plugin: p, name: "NIH-RePORTER", src: &et.Source{Name: "NIH-RePORTER", Confidence: 80}, run: queryNIH},
		{plugin: p, name: "SBIR", src: &et.Source{Name: "SBIR", Confidence: 80}, run: querySBIR},
	}
	return p
}

func (p *usgrants) Name() string { return p.name }

func (p *usgrants) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	for _, s := range p.srcs {
		if err := r.RegisterHandler(&et.Handler{
			Plugin:       p,
			Name:         p.name + "-" + s.name + "-Handler",
			Position:     42,
			Exclusive:    true,
			MaxInstances: support.MinHandlerInstances,
			Transforms: []string{
				string(oam.FundsTransfer),
				string(oam.Account),
				string(oam.Organization),
			},
			EventType: oam.Organization,
			Callback:  s.check,
		}); err != nil {
			return err
		}
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *usgrants) Stop() { p.log.Info("Plugin stopped") }

// check runs one source's query for an organization, respecting the TTL.
func (h *source) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.FundsTransfer), h.src.Name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, h.src, since) {
		return nil
	}
	h.run(h, e, e.Entity, o.Name)
	support.MarkAssetMonitored(e.Session, e.Entity, h.src)
	return nil
}

func (p *usgrants) createRelation(ctx context.Context, session et.Session, obj *dbt.Entity,
	rel oam.Relation, subject *dbt.Entity, src *et.Source) error {
	edge, err := session.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: obj, ToEntity: subject})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}
	_, err = session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source: src.Name, Confidence: src.Confidence,
	})
	return err
}
