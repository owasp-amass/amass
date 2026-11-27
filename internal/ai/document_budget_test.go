// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/collect"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// budgetStore is a companionStore in which the listed entities have edges.
type budgetStore struct {
	companionStore
	linked map[string]bool
}

func (s *budgetStore) IncomingEdges(_ context.Context, e *dbt.Entity, _ time.Time, _ ...string) ([]*dbt.Edge, error) {
	if s.linked[e.ID] {
		return []*dbt.Edge{{ID: "e-" + e.ID}}, nil
	}
	return nil, fmt.Errorf("zero edges found for entity %s", e.ID)
}

// The lead budget starts at the initial allowance, grows with each confirmed
// lead while at least half are confirmed, stops growing below that, and never
// passes the run's share or max_leads.
func TestLeadAllowance(t *testing.T) {
	ctx := context.Background()
	store := &budgetStore{companionStore: companionStore{runStore{props: map[string]oam.Property{}}},
		linked: map[string]bool{}}
	c := &DocumentCompanion{Store: store}
	done := 0
	act := collect.Activity{Progress: func() (int, int) { return done, done }}
	now := time.Now()

	st := &companionRun{}
	if got := c.allowance(ctx, st, act, now); got != InitialDocumentLeads {
		t.Fatalf("initial allowance %d", got)
	}

	submit := func(n, linked int) {
		st.submitted = nil
		store.linked = map[string]bool{}
		for i := range n {
			id := fmt.Sprintf("lead-%d", i)
			st.submitted = append(st.submitted, &submittedLead{entityID: id, at: now.Add(-time.Hour)})
			if i < linked {
				store.linked[id] = true
			}
		}
	}

	// two thirds confirmed in a large run: 50 + 2 per confirmed lead
	done = 2000
	submit(30, 20)
	if got := c.allowance(ctx, st, act, now); got != InitialDocumentLeads+2*20 {
		t.Fatalf("allowance with 20 of 30 confirmed: %d", got)
	}
	// the run's share caps it: 300 work items allow 50 at most
	done = 300
	if got := c.allowance(ctx, st, act, now); got != InitialDocumentLeads {
		t.Fatalf("allowance capped by a small run: %d", got)
	}
	// a third confirmed: no new leads
	done = 2000
	submit(30, 10)
	if got := c.allowance(ctx, st, act, now); got != 30 {
		t.Fatalf("allowance with 10 of 30 confirmed: %d", got)
	}
	// a few early leads going nowhere do not hold new ones back
	submit(4, 0)
	if got := c.allowance(ctx, st, act, now); got != InitialDocumentLeads {
		t.Fatalf("allowance with 0 of 4 confirmed: %d", got)
	}
	// max_leads caps it
	c.MaxLeads = 20
	submit(10, 10)
	if got := c.allowance(ctx, st, act, now); got != 20 {
		t.Fatalf("allowance under max_leads 20: %d", got)
	}
	// leads younger than the check age do not count yet
	c.MaxLeads = 0
	submit(10, 0)
	for _, s := range st.submitted {
		s.at = now
	}
	if got := c.allowance(ctx, st, act, now); got != InitialDocumentLeads {
		t.Fatalf("allowance with unchecked leads: %d", got)
	}
}
