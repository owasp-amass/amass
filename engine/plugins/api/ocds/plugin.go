// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package ocds collects public-procurement awards published in the Open
// Contracting Data Standard (OCDS) for an enumerated Organization. When the
// organization is the supplier on an award, the award is stored as a
// FundsTransfer the funding lens surfaces, with the buyer (contracting body) as
// the funding party. This internationalizes funding beyond the US and EU.
//
// OCDS standardizes the data, so one parser reads every publisher; what differs
// is each publisher's query API, which is data in publishers.json. A publisher
// is queried only when it is enabled and its query_url supports searching by
// supplier — many publishers offer only bulk or date paging, and some economies
// publish no open procurement data, so coverage grows as supplier-searchable
// endpoints are confirmed against real samples. Keyless and on by default;
// rate-limited; TTL cadence.
package ocds

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
	"golang.org/x/time/rate"
)

type ocds struct {
	name    string
	rlimit  *rate.Limiter
	source  *et.Source
	log     *slog.Logger
	handler *handler
}

type handler struct {
	name   string
	plugin *ocds
}

// NewOCDS returns the Open Contracting (OCDS) procurement-award collector.
func NewOCDS() et.Plugin {
	return &ocds{
		name:   "OCDS",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
		source: &et.Source{Name: "OCDS", Confidence: 80},
	}
}

func (o *ocds) Name() string { return o.name }

func (o *ocds) Start(r et.Registry) error {
	o.log = r.Log().WithGroup("plugin").With("name", o.name)

	o.handler = &handler{name: o.name + "-Awards-Handler", plugin: o}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       o,
		Name:         o.handler.name,
		Position:     42,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.FundsTransfer),
			string(oam.Account),
			string(oam.Organization),
		},
		EventType: oam.Organization,
		Callback:  o.handler.check,
	}); err != nil {
		return err
	}

	o.log.Info("Plugin started")
	return nil
}

func (o *ocds) Stop() { o.log.Info("Plugin stopped") }

func (o *ocds) createRelation(ctx context.Context, session et.Session, obj *dbt.Entity,
	rel oam.Relation, subject *dbt.Entity, conf int) error {
	edge, err := session.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: obj, ToEntity: subject})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}
	_, err = session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source: o.source.Name, Confidence: conf,
	})
	return err
}
