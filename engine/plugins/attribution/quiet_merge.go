// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package attribution

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/coord"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// defaultMergeQuiet is how long neither organization of a strong merge
// proposal may have been written to before the merge is applied while the
// enumeration still runs.
const defaultMergeQuiet = 5 * time.Minute

// quietMerges applies, while the enumeration runs, the pending merge
// proposals the drain pass would apply (proposed, and mergeable on their
// evidence without a person, compared afresh), once neither organization has
// been written to for mergeQuiet by any session: until then, every
// collector that works per organization and every attribution pass does
// each one twice. A pair still being written to waits, since a handler may
// still hold the duplicate; the duplicates of those pairs are returned so
// the attribution pass skips them meanwhile. Only auto mode merges, one
// engine at a time, as the drain pass does.
func (t *tracker) quietMerges(ctx context.Context, adapter oamrepo.Adapter) map[string]struct{} {
	if t.mode != config.AttributionAuto || t.journal == nil || t.p.mergeCheck <= 0 {
		return nil
	}

	state, err := t.journal.DuplicateState()
	if err != nil {
		return nil
	}

	t.mu.Lock()
	var pending []*review.DuplicateEntry
	for _, e := range state {
		if e == nil || e.Status != review.ProposalPending || e.Proposal.Decision != lens.GapPropose {
			continue
		}

		_, survivor := t.allOrgs[e.Proposal.SurvivorID]
		_, duplicate := t.allOrgs[e.Proposal.DuplicateID]
		if survivor || duplicate {
			pending = append(pending, e)
		}
	}
	t.mu.Unlock()
	if len(pending) == 0 {
		return nil
	}

	sort.Slice(pending, func(i, j int) bool { return pending[i].Proposal.ID < pending[j].Proposal.ID })
	t.p.mergeMu.Lock()
	defer t.p.mergeMu.Unlock()

	release, ok := coord.OpenLeases(t.sess.DB()).Hold(ctx, mergeLease, mergeLeaseTTL)
	if !ok {
		return nil
	}
	defer release()

	waiting := map[string]struct{}{}
	for _, e := range pending {
		p := e.Proposal
		if !t.autoMergeable(ctx, adapter, p) {
			continue
		}
		if !t.quiet(ctx, p.SurvivorID, p.DuplicateID) {
			waiting[p.DuplicateID] = struct{}{}
			continue
		}

		if _, err := review.ApplyMerge(ctx, adapter, t.journal, p, review.AutomaticReviewer); err != nil {
			t.sess.Log().Info(fmt.Sprintf("AI duplicate merge %s skipped: %v", p.ID, err))
			continue
		}

		t.forgetOrg(p.DuplicateID)
		t.sess.Log().Info(fmt.Sprintf("AI merged duplicate organization %s [%s] into %s [%s] while the "+
			"enumeration runs (proposal %s)", p.Duplicate, p.DuplicateID, p.Survivor, p.SurvivorID, p.ID))
	}

	return waiting
}

// autoMergeable compares the pair again and reports whether the drain pass
// would apply its merge: proposed, on evidence that needs no person.
func (t *tracker) autoMergeable(ctx context.Context, adapter oamrepo.Adapter, p review.DuplicateProposal) bool {
	report, err := lens.CompareOrganizations(ctx, adapter, []string{p.SurvivorID}, []string{p.DuplicateID})
	if err != nil {
		return false
	}

	for _, c := range report.Candidates {
		if review.DuplicateProposalID(c.Survivor, c.Duplicate) == p.ID {
			return c.Decision == lens.GapPropose && lens.AutoMergeable(c.Signals)
		}
	}

	return false
}

// quiet reports whether no session has written the organizations, their
// properties or their relations for mergeQuiet.
func (t *tracker) quiet(ctx context.Context, ids ...string) bool {
	db := t.sess.DB()
	since := time.Now().Add(-t.p.mergeQuiet)
	for _, id := range ids {
		ent, err := db.FindEntityById(ctx, id)
		if err != nil || ent == nil || ent.LastSeen.After(since) {
			return false
		}

		// an empty read can come back as an error, so only what is read counts
		tags, _ := db.FindEntityTags(ctx, ent, since)
		in, _ := db.IncomingEdges(ctx, ent, since)
		out, _ := db.OutgoingEdges(ctx, ent, since)
		if len(tags) > 0 || len(in) > 0 || len(out) > 0 || ctx.Err() != nil {
			return false
		}
	}

	return true
}

// forgetOrg stops tracking an organization a merge removed.
func (t *tracker) forgetOrg(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.orgs, id)
	delete(t.allOrgs, id)
	delete(t.dupProcessed, id)
}
