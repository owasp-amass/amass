// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/review"
	oam "github.com/owasp-amass/open-asset-model"
)

// The lead budget adapts to how the run's leads fare: it starts at
// InitialDocumentLeads, each lead the engine confirms earns
// leadsPerConfirmation more while at least leadConfirmationRate of the leads
// checked so far are confirmed, and below that rate new leads wait. The
// ceiling is a share of the run itself: one lead per leadRunShare work items
// the run has completed (never below the initial allowance), or max_leads
// when that is lower.
const (
	InitialDocumentLeads = 50
	leadsPerConfirmation = 2
	leadConfirmationRate = 0.5
	// leadCheckAge is how long the engine gets with a lead before it counts
	// toward the confirmation rate.
	leadCheckAge = 2 * time.Minute
	leadRunShare = 10
	// leadRateSample is how many leads must have been checked before the
	// confirmation rate can hold new leads back: a few early leads going
	// nowhere say little.
	leadRateSample = 10
	// leadRecheckInterval is how often an unconfirmed lead is checked again;
	// a check walks the stored relations around the lead.
	leadRecheckInterval = time.Minute
)

// submittedLead is a lead given to the run, and whether the engine has
// confirmed it yet.
type submittedLead struct {
	entityID  string
	at        time.Time
	confirmed bool
	checkedAt time.Time
}

// leadTargets returns a plan's targets, which a lead must be tied to before
// it counts as confirmed: its scope value and the targets it adds.
func leadTargets(p collect.Plan) review.LeadTargets {
	var assets []oam.Asset
	for _, e := range p.Entries() {
		if a, err := e.Asset(); err == nil {
			assets = append(assets, a)
		}
	}
	return review.NewLeadTargets(assets)
}

// queuedLead is a lead waiting for the budget to allow it.
type queuedLead struct {
	lead documentLead
	stmt review.StoredStatement
	doc  DocumentResult
	key  string
}

// allowance returns how many leads the run may have been given by now.
func (c *DocumentCompanion) allowance(ctx context.Context, st *companionRun, act collect.Activity,
	now time.Time) int {
	checked, confirmed := 0, 0
	for _, s := range st.submitted {
		if !s.confirmed && now.Sub(s.at) < leadCheckAge {
			continue
		}
		checked++
		if !s.confirmed && now.Sub(s.checkedAt) >= leadRecheckInterval {
			s.checkedAt = now
			s.confirmed = review.LeadConfirmed(ctx, c.Store, s.entityID, st.targets)
		}
		if s.confirmed {
			confirmed++
		}
	}

	allow := InitialDocumentLeads + leadsPerConfirmation*confirmed
	if checked >= leadRateSample && float64(confirmed) < leadConfirmationRate*float64(checked) {
		// most leads go nowhere: no new ones until that changes
		allow = len(st.submitted)
	}

	ceiling := InitialDocumentLeads
	if act.Progress != nil {
		if done, _ := act.Progress(); done/leadRunShare > ceiling {
			ceiling = done / leadRunShare
		}
	}
	if c.MaxLeads > 0 && c.MaxLeads < ceiling {
		ceiling = c.MaxLeads
	}
	return min(allow, ceiling)
}

// drain submits the queued leads the budget allows, oldest first.
func (c *DocumentCompanion) drain(ctx context.Context, run collect.Run, act collect.Activity, st *companionRun) {
	if len(st.queue) == 0 || act.Submit == nil {
		return
	}

	allow := c.allowance(ctx, st, act, time.Now())
	for len(st.submitted) < allow && len(st.queue) > 0 {
		if ctx.Err() != nil {
			return
		}
		q := st.queue[0]
		st.queue = st.queue[1:]
		count(act, ActivityLeadsWaiting, -1)

		id, err := act.Submit(ctx, q.lead.asset)
		if err != nil || id == "" {
			continue
		}
		st.submitted = append(st.submitted, &submittedLead{entityID: id, at: time.Now()})
		count(act, ActivityLeads, 1)
		_, _ = review.RecordDocumentLead(ctx, c.Store, c.Journal, review.DocumentLead{RunID: run.ID,
			EntityID: id, Name: q.lead.name, Type: string(q.lead.asset.AssetType()), FileID: q.doc.FileID,
			URL: q.doc.URL, Predicate: leadPredicate(q.stmt), Model: c.ModelID})
	}
}
