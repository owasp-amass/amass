// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package usaspending collects United States federal awards (contracts, grants,
// loans and direct payments) made to an enumerated Organization from the public
// USAspending.gov API, and stores each as a FundsTransfer the funding lens
// surfaces, with the awarding agency as the funding party.
//
// The source is keyless and runs by default, no setup required. A run against a
// non-US organization — which USAspending cannot match — simply stores nothing,
// as does a US organization with no federal awards; requests are rate-limited
// and follow the TTL cadence. This is one regional funder source among many;
// others write the same FundsTransfer shape (see
// claude/government-funding-sources-spec.md).
package usaspending

import (
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"golang.org/x/time/rate"
)

type usaspending struct {
	name   string
	api    string
	rlimit *rate.Limiter
	source *et.Source
	log    *slog.Logger
	awards *awards
}

type awards struct {
	name   string
	plugin *usaspending
}

// NewUSASpending returns the USAspending.gov federal-award collector.
func NewUSASpending() et.Plugin {
	return &usaspending{
		name:   "USAspending",
		api:    "https://api.usaspending.gov/api/v2",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
		source: &et.Source{
			Name: "USAspending",
			// Authoritative data, but recipients are matched by name, so the
			// confidence leaves room for a same-name mismatch.
			Confidence: 80,
		},
	}
}

func (u *usaspending) Name() string { return u.name }

func (u *usaspending) Start(r et.Registry) error {
	u.log = r.Log().WithGroup("plugin").With("name", u.name)

	u.awards = &awards{name: u.name + "-Awards-Handler", plugin: u}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       u,
		Name:         u.awards.name,
		Position:     42,
		Exclusive:    false,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.FundsTransfer),
			string(oam.Account),
			string(oam.Organization),
		},
		EventType: oam.Organization,
		Callback:  u.awards.check,
	}); err != nil {
		return err
	}

	u.log.Info("Plugin started")
	return nil
}

func (u *usaspending) Stop() { u.log.Info("Plugin stopped") }
