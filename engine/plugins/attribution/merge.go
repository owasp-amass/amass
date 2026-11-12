// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package attribution

import (
	"context"
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/oamrepo"
)

const (
	// defaultMergeCheck is how often the merge watcher checks whether the
	// enumeration's other work has drained.
	defaultMergeCheck = 2 * time.Second
	// mergeSettled is how many checks in a row must find the other work
	// drained before merges run.
	mergeSettled = 2
	// mergeTimeout bounds the duplicate search and its merges.
	mergeTimeout = 5 * time.Minute
)

// watchMerges finds duplicate organizations once the session's other work
// has drained, records the merge proposals in the journal and, in auto
// mode, applies the proposed merges. It also records contradicted legal
// identities and each enumerated domain's departments for review, and in
// auto mode first retracts automatic ownership writes whose evidence is gone. Merges also wait for the engine's other sessions to
// drain, and one merge pass runs at a time. Merging earlier could delete an
// organization a plugin is still writing to. The watcher holds one unit of
// background work, counted by its caller, so the session is not reported
// finished before the merges run; it releases the unit when it returns.
func (t *tracker) watchMerges() {
	defer t.sess.Stats().AddBackground(-1)

	settled := 0
	tick := time.NewTicker(t.p.mergeCheck)
	defer tick.Stop()
	for {
		select {
		case <-t.sess.Ctx().Done():
			return
		case <-tick.C:
		}
		if t.sess.Done() {
			return
		}
		// Another enumeration on the same database may still be writing to
		// an organization a merge would delete.
		if !t.drained() || t.p.othersBusy(t) {
			settled = 0
			continue
		}

		settled++
		if settled >= mergeSettled {
			t.p.mergeMu.Lock()
			t.mergeDuplicates()
			t.p.mergeMu.Unlock()
			return
		}
	}
}

// othersBusy reports whether any other session of this engine still has
// work besides background work, such as its own merge watcher.
func (p *plugin) othersBusy(self *tracker) bool {
	p.mu.Lock()
	others := make([]*tracker, 0, len(p.sessions))
	for _, t := range p.sessions {
		if t != self {
			others = append(others, t)
		}
	}
	p.mu.Unlock()

	for _, t := range others {
		if !t.sess.Done() && t.sess.Ctx().Err() == nil && !t.drained() {
			return true
		}
	}

	return false
}

// drained reports whether only background work remains and no attribution
// pass is pending.
func (t *tracker) drained() bool {
	if t.busy() {
		return false
	}

	stats := t.sess.Stats()
	stats.RLock()
	total, completed := stats.WorkItemsTotal, stats.WorkItemsCompleted
	stats.RUnlock()

	return total-completed <= stats.Background()
}

// mergeDuplicates records the duplicate organizations as merge proposals
// and, in auto mode, merges the proposed pairs that are still pending.
func (t *tracker) mergeDuplicates() {
	ctx, cancel := context.WithTimeout(t.sess.Ctx(), mergeTimeout)
	defer cancel()

	adapter := oamrepo.Adapter{Repo: t.sess.DB(), Neo4jDatabase: oamrepo.Neo4jDatabaseName(t.sess.Config())}
	if t.mode == config.AttributionAuto {
		t.recheck(ctx, adapter)
	}

	report, err := ai.FindDuplicateOrganizations(ctx, adapter)
	if err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI duplicate search: %v", err))
		return
	}

	if _, err := t.journal.SubmitDuplicates(ai.DuplicateProposals(report)); err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI duplicate search could not record proposals: %v", err))
		return
	}

	merged := 0
	if t.mode == config.AttributionAuto {
		state, err := t.journal.DuplicateState()
		if err != nil {
			t.sess.Log().Error(fmt.Sprintf("AI duplicate search could not read the journal: %v", err))
			return
		}

		for _, c := range report.Candidates {
			id := ai.DuplicateProposalID(c.Survivor, c.Duplicate)
			e, ok := state[id]
			// Only proposed pairs nobody has decided on: a rejected or undone
			// merge is never applied again.
			if !ok || c.Decision != ai.GapPropose || e.Status != ai.ProposalPending {
				continue
			}

			if _, err := ai.ApplyMerge(ctx, adapter, t.journal, e.Proposal, ai.AutomaticReviewer); err != nil {
				// An earlier merge in this pass can remove one of the pair.
				t.sess.Log().Info(fmt.Sprintf("AI duplicate merge %s skipped: %v", id, err))
				continue
			}

			merged++
			t.sess.Log().Info(fmt.Sprintf("AI merged duplicate organization %s [%s] into %s [%s] (proposal %s)",
				e.Proposal.Duplicate, e.Proposal.DuplicateID, e.Proposal.Survivor, e.Proposal.SurvivorID, id))
		}
	}

	t.recordIdentityConflicts(ctx, adapter)
	t.recordFamilies(ctx, adapter)

	state, err := t.journal.DuplicateState()
	if err != nil {
		return
	}

	pending := 0
	for _, p := range ai.DuplicateProposals(report) {
		if e, ok := state[p.ID]; ok && e.Status == ai.ProposalPending {
			pending++
		}
	}
	if pending > 0 || merged > 0 {
		t.sess.Log().Info(fmt.Sprintf("AI duplicate search compared %d organizations: %d merged, %d merge "+
			"proposal(s) waiting for review in %s", report.Organizations, merged, pending, t.journal.Path))
	}
}

// recordIdentityConflicts records the organizations whose legal identity
// contradicts their own evidence. A correction is never applied
// automatically: companies do rename and relocate.
func (t *tracker) recordIdentityConflicts(ctx context.Context, adapter oamrepo.Adapter) {
	report, err := ai.FindIdentityConflicts(ctx, adapter)
	if err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI identity check: %v", err))
		return
	}

	added, err := t.journal.SubmitIdentityConflicts(report.Conflicts)
	if err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI identity check could not record proposals: %v", err))
		return
	}
	if len(added) > 0 {
		t.sess.Log().Info(fmt.Sprintf("AI identity check found %d organization(s) whose legal identity contradicts "+
			"their evidence; corrections are waiting for review in %s", len(added), t.journal.Path))
	}
}

// recordFamilies records, for each enumerated domain, the departments of
// its organization family as org_unit proposals and its same-institution
// organizations as merge proposals. Neither is applied automatically.
func (t *tracker) recordFamilies(ctx context.Context, adapter oamrepo.Adapter) {
	for _, d := range t.sess.Config().Domains() {
		res, err := adapter.ResolveAsset(ctx, ai.AssetSelector{Type: "FQDN", Field: "name", Value: d}, 2)
		if err != nil || len(res.Candidates) != 1 {
			continue
		}

		r, err := ai.FindOrganizationFamily(ctx, adapter, res.Candidates[0].Asset)
		if err != nil {
			t.sess.Log().Error(fmt.Sprintf("AI family of %s: %v", d, err))
			continue
		}

		units, merges, err := t.journal.SubmitFamily(r)
		if err != nil {
			t.sess.Log().Error(fmt.Sprintf("AI family of %s could not record proposals: %v", d, err))
			continue
		}
		if units+merges > 0 {
			t.sess.Log().Info(fmt.Sprintf("AI family of %s: %d department and %d merge proposal(s) waiting for "+
				"review in %s", d, units, merges, t.journal.Path))
		}
	}
}

// recheck retracts the automatic ownership writes whose evidence is gone;
// the next pass writes them again if what remains still supports them.
func (t *tracker) recheck(ctx context.Context, adapter oamrepo.Adapter) {
	res, err := ai.RecheckAttributions(ctx, adapter, adapter, t.journal)
	if err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI attribution re-check: %v", err))
		return
	}

	for _, p := range res.Retracted {
		t.sess.Log().Info(fmt.Sprintf("AI attribution retracted %s %s as owned by %s: its evidence is gone "+
			"(proposal %s)", p.AssetType, p.Asset, p.Owner, p.ID))
	}
}
