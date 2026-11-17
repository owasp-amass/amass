// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package osm collects organization phone numbers from OpenStreetMap through the
// public Overpass API, a worldwide, keyless source. For an enumerated
// Organization it looks up map features whose name matches and that carry a
// phone (phone / contact:phone) tag, and stores each number as a Phone under a
// ContactRecord, with the OpenStreetMap feature URL as the evidence.
//
// This is a global source, unlike the US-specific funders, so it helps targets
// anywhere. It is keyless but opt-in (enabled only when listed in the
// data-source configuration), because Overpass is a shared community service.
// Because a map feature's name matching an organization does not prove it
// belongs to that organization, matching is conservative (normalized-name
// equality) and the stored confidence is modest; the numbers are observations
// carrying their source, not computed conclusions (see
// claude/government-funding-sources-spec.md).
package osm

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

type openstreetmap struct {
	name   string
	api    string
	rlimit *rate.Limiter
	source *et.Source
	log    *slog.Logger
	phones *phones
}

type phones struct {
	name   string
	plugin *openstreetmap
}

// NewOpenStreetMap returns the OpenStreetMap/Overpass phone collector.
func NewOpenStreetMap() et.Plugin {
	return &openstreetmap{
		name: "OpenStreetMap",
		api:  "https://overpass-api.de/api/interpreter",
		// Overpass is a shared community service; query it gently.
		rlimit: rate.NewLimiter(rate.Every(5*time.Second), 1),
		source: &et.Source{
			Name: "OpenStreetMap",
			// A matching feature name is suggestive, not proof of ownership.
			Confidence: 60,
		},
	}
}

func (o *openstreetmap) Name() string { return o.name }

func (o *openstreetmap) Start(r et.Registry) error {
	o.log = r.Log().WithGroup("plugin").With("name", o.name)

	o.phones = &phones{name: o.name + "-Phones-Handler", plugin: o}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       o,
		Name:         o.phones.name,
		Position:     42,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.ContactRecord),
			string(oam.Phone),
		},
		EventType: oam.Organization,
		Callback:  o.phones.check,
	}); err != nil {
		return err
	}

	o.log.Info("Plugin started")
	return nil
}

func (o *openstreetmap) Stop() { o.log.Info("Plugin stopped") }

func (o *openstreetmap) createRelation(ctx context.Context, session et.Session, obj *dbt.Entity,
	rel oam.Relation, subject *dbt.Entity, conf int) error {
	edge, err := session.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: obj, ToEntity: subject})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}

	_, err = session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     o.source.Name,
		Confidence: conf,
	})
	return err
}
