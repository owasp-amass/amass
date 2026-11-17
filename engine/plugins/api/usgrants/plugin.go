// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package usgrants collects United States federal research grants made to an
// enumerated Organization from three keyless public APIs — NSF Award Search,
// NIH RePORTER and SBIR/STTR — and stores each as a FundsTransfer the funding
// lens surfaces, with the funding agency as the funding party. These complement
// the USAspending collector (contracts/assistance) with research-grant funding.
//
// Each source is its own plugin, named for the source (NSF, NIH-RePORTER,
// SBIR), so a user can opt any one of them out individually by name through the
// transformations exclude list, like any other data source. All are keyless and
// run by default; each applies only to US recipients (a non-US organization
// matches nothing). Recipients are matched to the subject by normalized name,
// requests are rate-limited, and collection follows the TTL cadence.
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

// source is one grant API, which is also its own plugin so it carries a source
// name users can exclude individually.
type source struct {
	name   string
	src    *et.Source
	rlimit *rate.Limiter
	log    *slog.Logger
	run    func(h *source, e *et.Event, orgent *dbt.Entity, name string)
}

// NewNSF, NewNIH and NewSBIR are the three grant-source plugins.
func NewNSF() et.Plugin  { return newSource("NSF", queryNSF) }
func NewNIH() et.Plugin  { return newSource("NIH-RePORTER", queryNIH) }
func NewSBIR() et.Plugin { return newSource("SBIR", querySBIR) }

func newSource(name string, run func(*source, *et.Event, *dbt.Entity, string)) *source {
	return &source{
		name:   name,
		src:    &et.Source{Name: name, Confidence: 80},
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
		run:    run,
	}
}

func (h *source) Name() string { return h.name }

func (h *source) Start(r et.Registry) error {
	h.log = r.Log().WithGroup("plugin").With("name", h.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       h,
		Name:         h.name + "-Handler",
		Position:     42,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.FundsTransfer),
			string(oam.Account),
			string(oam.Organization),
		},
		EventType: oam.Organization,
		Callback:  h.check,
	}); err != nil {
		return err
	}

	h.log.Info("Plugin started")
	return nil
}

func (h *source) Stop() {
	if h.log != nil {
		h.log.Info("Plugin stopped")
	}
}

// check runs this source's query for an organization, respecting the TTL.
func (h *source) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.FundsTransfer), h.name)
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

func (h *source) createRelation(ctx context.Context, session et.Session, obj *dbt.Entity,
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
