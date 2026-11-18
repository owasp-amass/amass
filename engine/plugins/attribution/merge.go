// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package attribution

import (
	"context"
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	orgsupport "github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oamorg "github.com/owasp-amass/open-asset-model/org"
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
	// defaultOthersWait is how long, once its own work has drained, a
	// session in auto mode waits for the engine's other sessions before it
	// records its proposals without applying them. It is well inside the
	// enum client's default 30 minutes without progress.
	defaultOthersWait = 10 * time.Minute
)

// watchMerges finds duplicate organizations once the session's own work
// has drained and records the merge proposals in the journal. It also
// records contradicted legal identities and each enumerated domain's
// departments for review. In auto mode it then applies the proposed merges,
// first retracting automatic ownership writes whose evidence is gone; those
// writes also wait for the engine's other sessions to drain, since merging
// earlier could delete an organization another session is still writing
// to, and one pass runs at a time. When other sessions stay busy longer
// than othersWait, the proposals are recorded without being applied, for
// review or a later run: a long enumeration elsewhere must not hold this
// session open (the enum client ends a session after its timeout without
// progress) or keep its proposals from being recorded. The watcher holds
// one unit of background work, counted by its caller, so the session is not
// reported finished before the pass runs; it releases the unit when it
// returns.
func (t *tracker) watchMerges() {
	defer t.sess.Stats().AddBackground(-1)

	settled := 0
	var drainedAt time.Time
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
		if !t.drained() {
			settled, drainedAt = 0, time.Time{}
			continue
		}
		if drainedAt.IsZero() {
			drainedAt = time.Now()
		}

		// Only auto mode writes, so only it waits for other sessions.
		write := t.mode == config.AttributionAuto
		if write && t.p.othersBusy(t) {
			if time.Since(drainedAt) < t.p.othersWait {
				settled = 0
				continue
			}

			write = false
			t.sess.Log().Info("AI duplicate search records its merge proposals without applying them: other " +
				"enumerations on this engine are still writing")
		}

		settled++
		if settled >= mergeSettled {
			t.p.mergeMu.Lock()
			t.mergeDuplicates(write)
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
// and, when write is set, merges the proposed pairs that are still pending
// after retracting automatic writes whose evidence is gone.
func (t *tracker) mergeDuplicates(write bool) {
	ctx, cancel := context.WithTimeout(t.sess.Ctx(), mergeTimeout)
	defer cancel()

	adapter := oamrepo.Adapter{Repo: t.sess.DB(), Neo4jDatabase: oamrepo.Neo4jDatabaseName(t.sess.Config())}
	if write {
		t.recheck(ctx, adapter)
	}

	report, err := t.duplicateReport(ctx, adapter)
	if err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI duplicate search: %v", err))
		return
	}

	if _, err := t.journal.SubmitDuplicates(review.DuplicateProposals(report)); err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI duplicate search could not record proposals: %v", err))
		return
	}

	merged := 0
	if write {
		state, err := t.journal.DuplicateState()
		if err != nil {
			t.sess.Log().Error(fmt.Sprintf("AI duplicate search could not read the journal: %v", err))
			return
		}

		for _, c := range report.Candidates {
			id := review.DuplicateProposalID(c.Survivor, c.Duplicate)
			e, ok := state[id]
			// Only proposed pairs nobody has decided on: a rejected or undone
			// merge is never applied again.
			if !ok || c.Decision != lens.GapPropose || e.Status != review.ProposalPending {
				continue
			}

			if _, err := review.ApplyMerge(ctx, adapter, t.journal, e.Proposal, review.AutomaticReviewer); err != nil {
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
	t.recordPersonDuplicates(ctx, adapter)

	state, err := t.journal.DuplicateState()
	if err != nil {
		return
	}

	pending := 0
	for _, p := range review.DuplicateProposals(report) {
		if e, ok := state[p.ID]; ok && e.Status == review.ProposalPending {
			pending++
		}
	}
	if pending > 0 || merged > 0 {
		t.sess.Log().Info(fmt.Sprintf("AI duplicate search compared %d organizations: %d merged, %d merge "+
			"proposal(s) waiting for review in %s", report.Organizations, merged, pending, t.journal.Path))
	}
}

// duplicateReport compares the organizations this enumeration touched — in
// scope or not, since the run created or re-touched them — against one another
// and against the others that share a name, identifier, phone or address with
// one of them, and returns the duplicate candidates. It drives
// the comparison from the touched organizations and bounded reverse lookups
// rather than a whole-database scan, so its cost tracks the enumeration's own
// size: a session that brings in a handful of organizations reads a handful of
// buckets, whatever the size of the database. The whole-database sweep remains
// available on demand as the `amass db duplicates` operation. A signal shared
// by more than lens.GapMaxShared organizations is too common to be meaningful,
// so that bucket is skipped, matching the sweep's handling of an over-full
// bucket and keeping the candidate set bounded.
func (t *tracker) duplicateReport(ctx context.Context, adapter oamrepo.Adapter) (lens.DuplicateReport, error) {
	t.mu.Lock()
	touched := make([]*dbt.Entity, 0, len(t.allOrgs))
	for _, o := range t.allOrgs {
		touched = append(touched, o)
	}
	t.mu.Unlock()

	return t.duplicateReportFor(ctx, adapter, touched)
}

// duplicateReportFor compares the given organizations against one another and
// against the others that share a name, identifier, phone or address with one
// of them, and returns the duplicate candidates. It is the bounded core the
// at-drain pass (over every touched organization) and the incremental pass
// (over the organizations touched since the last pass) both drive.
func (t *tracker) duplicateReportFor(ctx context.Context, adapter oamrepo.Adapter,
	touched []*dbt.Entity) (lens.DuplicateReport, error) {
	seedIDs := make([]string, 0, len(touched))
	candSet := make(map[string]struct{})
	for _, o := range touched {
		if o == nil || o.Asset == nil {
			continue
		}
		seedIDs = append(seedIDs, o.ID)

		var names []string
		if org, ok := o.Asset.(*oamorg.Organization); ok {
			for _, n := range []string{org.Name, org.LegalName} {
				if n != "" {
					names = append(names, n)
				}
			}
		}

		lookups := [][]*dbt.Entity{
			orgsupport.OrgsSharingName(t.sess, names),
			orgsupport.OrgsSharingIdentifier(t.sess, o),
			orgsupport.OrgsSharingPhone(t.sess, o),
			orgsupport.OrgsSharingAddress(t.sess, o),
		}
		for _, cands := range lookups {
			if len(cands) > lens.GapMaxShared {
				continue
			}
			for _, c := range cands {
				if c != nil && c.ID != o.ID {
					candSet[c.ID] = struct{}{}
				}
			}
		}
	}

	candidateIDs := make([]string, 0, len(candSet))
	for id := range candSet {
		candidateIDs = append(candidateIDs, id)
	}

	return lens.CompareOrganizations(ctx, adapter, seedIDs, candidateIDs)
}

// incrementalProposals raises duplicate and identity proposals for the
// organizations touched since the last pass, so they accumulate for review
// while the enumeration runs rather than only at drain. It records proposals
// only — nothing is merged until the drain pass — so it never deletes an
// organization another handler is still writing to. Each organization is
// compared once (tracked in dupProcessed), so the per-pass cost is bounded by
// what changed, not the run's total, and the de-dupe in the journal makes a
// proposal the drain pass also finds harmless.
func (t *tracker) incrementalProposals(ctx context.Context, adapter oamrepo.Adapter) {
	if t.journal == nil {
		return
	}

	t.mu.Lock()
	var delta []*dbt.Entity
	ids := make([]string, 0)
	for id, o := range t.allOrgs {
		if _, done := t.dupProcessed[id]; done {
			continue
		}
		t.dupProcessed[id] = struct{}{}
		delta = append(delta, o)
		ids = append(ids, id)
	}
	t.mu.Unlock()

	if len(delta) == 0 {
		return
	}

	if report, err := t.duplicateReportFor(ctx, adapter, delta); err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI incremental duplicate search: %v", err))
	} else if added, err := t.journal.SubmitDuplicates(review.DuplicateProposals(report)); err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI incremental duplicate search could not record proposals: %v", err))
	} else if len(added) > 0 {
		t.sess.Log().Info(fmt.Sprintf("AI duplicate search raised %d merge proposal(s) for review in %s",
			len(added), t.journal.Path))
	}

	if report, err := lens.CheckIdentityConflicts(ctx, adapter, ids); err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI incremental identity check: %v", err))
	} else if added, err := t.journal.SubmitIdentityConflicts(report.Conflicts); err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI incremental identity check could not record proposals: %v", err))
	} else if len(added) > 0 {
		t.sess.Log().Info(fmt.Sprintf("AI identity check raised %d correction(s) for review in %s",
			len(added), t.journal.Path))
	}
}

// personDuplicates raises review-gated person-merge proposals for the given
// seed persons, comparing each against the persons it shares an organization or
// identifier with. Record-only: a person merge is never applied automatically.
func (t *tracker) personDuplicates(ctx context.Context, adapter oamrepo.Adapter, seedIDs []string) {
	if t.journal == nil || len(seedIDs) == 0 {
		return
	}

	candSet := map[string]struct{}{}
	for _, id := range seedIDs {
		for _, c := range lens.PersonCandidates(ctx, adapter, id) {
			candSet[c] = struct{}{}
		}
	}
	candIDs := make([]string, 0, len(candSet))
	for id := range candSet {
		candIDs = append(candIDs, id)
	}

	report, err := lens.ComparePersons(ctx, adapter, seedIDs, candIDs)
	if err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI person-duplicate search: %v", err))
		return
	}
	if added, err := t.journal.SubmitDuplicates(review.PersonDuplicateProposals(report)); err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI person-duplicate search could not record proposals: %v", err))
	} else if len(added) > 0 {
		t.sess.Log().Info(fmt.Sprintf("AI person-duplicate search raised %d merge proposal(s) for review in %s",
			len(added), t.journal.Path))
	}
}

// incrementalPersonProposals raises person-merge proposals for the persons
// touched since the last pass, so they accumulate mid-run.
func (t *tracker) incrementalPersonProposals(ctx context.Context, adapter oamrepo.Adapter) {
	t.mu.Lock()
	var seedIDs []string
	for id := range t.allPersons {
		if _, done := t.personProcessed[id]; done {
			continue
		}
		t.personProcessed[id] = struct{}{}
		seedIDs = append(seedIDs, id)
	}
	t.mu.Unlock()

	t.personDuplicates(ctx, adapter, seedIDs)
}

// recordPersonDuplicates raises person-merge proposals for every person the run
// touched, at drain, so a run that touched persons but no in-scope organization
// (and so ran no incremental pass) still has them compared.
func (t *tracker) recordPersonDuplicates(ctx context.Context, adapter oamrepo.Adapter) {
	t.mu.Lock()
	ids := make([]string, 0, len(t.allPersons))
	for id := range t.allPersons {
		ids = append(ids, id)
	}
	t.mu.Unlock()

	t.personDuplicates(ctx, adapter, ids)
}

// recordIdentityConflicts records the organizations whose legal identity
// contradicts their own evidence. A correction is never applied
// automatically: companies do rename and relocate.
func (t *tracker) recordIdentityConflicts(ctx context.Context, adapter oamrepo.Adapter) {
	// Check only the organizations this enumeration touched, so the cost tracks
	// the run rather than the whole database. The whole-database sweep stays
	// available on demand as `amass db identity`.
	t.mu.Lock()
	ids := make([]string, 0, len(t.allOrgs))
	for id := range t.allOrgs {
		ids = append(ids, id)
	}
	t.mu.Unlock()

	report, err := lens.CheckIdentityConflicts(ctx, adapter, ids)
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
		res, err := adapter.ResolveAsset(ctx, graph.AssetSelector{Type: "FQDN", Field: "name", Value: d}, 2)
		if err != nil || len(res.Candidates) != 1 {
			continue
		}

		r, err := lens.FindOrganizationFamily(ctx, adapter, res.Candidates[0].Asset)
		if err != nil {
			t.sess.Log().Error(fmt.Sprintf("AI family of %s: %v", d, err))
			continue
		}

		units, merges, err := review.SubmitFamily(t.journal, r)
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
	res, err := review.RecheckAttributions(ctx, adapter, adapter, t.journal)
	if err != nil {
		t.sess.Log().Error(fmt.Sprintf("AI attribution re-check: %v", err))
		return
	}

	for _, p := range res.Retracted {
		t.sess.Log().Info(fmt.Sprintf("AI attribution retracted %s %s as owned by %s: its evidence is gone "+
			"(proposal %s)", p.AssetType, p.Asset, p.Owner, p.ID))
	}
}
