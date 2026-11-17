// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package ted collects European Union public-procurement awards from Tenders
// Electronic Daily (the TED Search API, api.ted.europa.eu) for an enumerated
// Organization. When the organization is the winner of a contract, the award is
// stored as a FundsTransfer the funding lens surfaces, with the contracting
// authority (buyer) as the funding party — the EU analogue of the USAspending
// collector, broadening funding coverage beyond the US.
//
// The source is keyless and runs by default, no setup required; a target that
// never won an EU contract yields nothing. It is rate-limited and follows the
// TTL cadence. TED's field codes and query language are documented, but the
// exact shape of field VALUES in the response (scalar, list or multilingual
// map) is version-dependent, so the parser tolerates all three; the live
// response shape is worth a validation pass (see
// claude/government-funding-sources-spec.md).
package ted

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

type ted struct {
	name   string
	api    string
	rlimit *rate.Limiter
	source *et.Source
	log    *slog.Logger
	awards *awards
}

type awards struct {
	name   string
	plugin *ted
}

// NewTED returns the TED (EU procurement) award collector.
func NewTED() et.Plugin {
	return &ted{
		name:   "TED",
		api:    "https://api.ted.europa.eu/v3",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
		source: &et.Source{
			Name: "TED",
			// Winners are matched by name, so leave room for a mismatch.
			Confidence: 80,
		},
	}
}

func (t *ted) Name() string { return t.name }

func (t *ted) Start(r et.Registry) error {
	t.log = r.Log().WithGroup("plugin").With("name", t.name)

	t.awards = &awards{name: t.name + "-Awards-Handler", plugin: t}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       t,
		Name:         t.awards.name,
		Position:     42,
		Exclusive:    false,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.FundsTransfer),
			string(oam.Account),
			string(oam.Organization),
		},
		EventType: oam.Organization,
		Callback:  t.awards.check,
	}); err != nil {
		return err
	}

	t.log.Info("Plugin started")
	return nil
}

func (t *ted) Stop() { t.log.Info("Plugin stopped") }

func (t *ted) createRelation(ctx context.Context, session et.Session, obj *dbt.Entity,
	rel oam.Relation, subject *dbt.Entity, conf int) error {
	edge, err := session.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: obj, ToEntity: subject})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}

	_, err = session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     t.source.Name,
		Confidence: conf,
	})
	return err
}
