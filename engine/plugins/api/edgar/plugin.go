// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package edgar collects United States SEC EDGAR data for an enumerated
// Organization from the public data.sec.gov API. It resolves the organization
// to its SEC CIK, stores the CIK as an Identifier and the filer's
// business-address phone and postal address under a ContactRecord, and stores
// each Form D exempt-offering (private capital raise) as a FundsTransfer the
// funding lens surfaces.
//
// One keyless collector thus feeds two OAM types: FundsTransfer (Form D) and
// Phone (filer business address). It is keyless and runs by default, no setup
// required; it applies only to US filers (a non-US organization resolves to no
// CIK and nothing is stored). SEC requires a descriptive User-Agent and caps
// request rate, both honored here (see claude/government-funding-sources-spec.md).
package edgar

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"golang.org/x/time/rate"
)

// CIKIdentifier is the Identifier type stored for an SEC Central Index Key.
const CIKIdentifier = "SEC CIK"

// userAgent is the descriptive agent SEC asks automated clients to send.
const userAgent = "OWASP Amass (amass@owasp.org)"

type edgar struct {
	name     string
	api      string // data.sec.gov
	www      string // www.sec.gov
	rlimit   *rate.Limiter
	source   *et.Source
	log      *slog.Logger
	filings  *filings
	mu       sync.Mutex
	cikByOrg map[string]string // normalized org name -> 10-digit CIK
}

type filings struct {
	name   string
	plugin *edgar
}

// NewEDGAR returns the SEC EDGAR collector.
func NewEDGAR() et.Plugin {
	return &edgar{
		name: "SEC-EDGAR",
		api:  "https://data.sec.gov",
		www:  "https://www.sec.gov",
		// SEC asks clients to stay at or below 10 requests per second.
		rlimit: rate.NewLimiter(rate.Every(150*time.Millisecond), 1),
		source: &et.Source{
			Name: "SEC-EDGAR",
			// CIK is matched from the org name, so leave room for a mismatch.
			Confidence: 80,
		},
	}
}

func (ed *edgar) Name() string { return ed.name }

func (ed *edgar) Start(r et.Registry) error {
	ed.log = r.Log().WithGroup("plugin").With("name", ed.name)

	ed.filings = &filings{name: ed.name + "-Filings-Handler", plugin: ed}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       ed,
		Name:         ed.filings.name,
		Position:     42,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{
			string(oam.Identifier),
			string(oam.ContactRecord),
			string(oam.Phone),
			string(oam.Location),
			string(oam.FundsTransfer),
			string(oam.Account),
		},
		EventType: oam.Organization,
		Callback:  ed.filings.check,
	}); err != nil {
		return err
	}

	ed.log.Info("Plugin started")
	return nil
}

func (ed *edgar) Stop() { ed.log.Info("Plugin stopped") }

func (ed *edgar) createRelation(ctx context.Context, session et.Session, obj *dbt.Entity,
	rel oam.Relation, subject *dbt.Entity, conf int) error {
	edge, err := session.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: obj, ToEntity: subject})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}

	_, err = session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     ed.source.Name,
		Confidence: conf,
	})
	return err
}
