// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package propublica collects US nonprofit data for an enumerated Organization
// from the keyless ProPublica Nonprofit Explorer API (IRS Form 990 data). It
// resolves the organization to its EIN, stores the EIN as an Identifier and the
// filer's address under a ContactRecord, and — when a filing reports
// contributions and grants received — stores that as a FundsTransfer the funding
// lens surfaces.
//
// Its strongest value is identity and contact enrichment (EIN and address are
// correlation signals the affiliation work uses); the funding figure is an
// aggregate with no named funder, so it is recorded only when present. Keyless
// and on by default, US nonprofits only (a target with no 990 matches nothing),
// rate-limited, TTL cadence. See claude/government-funding-sources-spec.md.
package propublica

import (
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"golang.org/x/time/rate"
)

// EINIdentifier is the Identifier type stored for a US Employer Identification
// Number.
const EINIdentifier = "EIN"

type propublica struct {
	name    string
	api     string
	rlimit  *rate.Limiter
	source  *et.Source
	log     *slog.Logger
	filings *filings
}

type filings struct {
	name   string
	plugin *propublica
}

// NewProPublica returns the ProPublica Nonprofit Explorer collector.
func NewProPublica() et.Plugin {
	return &propublica{
		name:   "ProPublica",
		api:    "https://projects.propublica.org/nonprofits/api/v2",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
		source: &et.Source{Name: "ProPublica", Confidence: 80},
	}
}

func (p *propublica) Name() string { return p.name }

func (p *propublica) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	p.filings = &filings{name: p.name + "-Filings-Handler", plugin: p}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       p,
		Name:         p.filings.name,
		Position:     42,
		Exclusive:    false,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.Identifier),
			string(oam.ContactRecord),
			string(oam.StreetAddress),
			string(oam.FundsTransfer),
			string(oam.Account),
		},
		EventType: oam.Organization,
		Callback:  p.filings.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *propublica) Stop() { p.log.Info("Plugin stopped") }
