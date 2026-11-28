// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package attribution records ownership the evidence supports while an
// enumeration runs. When assets that carry ownership signals arrive, it
// finds the ownership gaps of the session's in-scope organizations, writes
// the strong proposals with an amass-ai source, widens the scope the same
// way the Horizontals plugin does, and leaves the rest in the review
// journal. It merges the duplicate organizations the evidence supports
// once no session has written to them for a while, and the rest of those
// the evidence supports once the enumeration's other work has drained. It
// needs no model.
package attribution

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

const (
	// defaultQuiet is how long the signals must be still before a pass runs.
	defaultQuiet = 5 * time.Second
	// defaultMaxWait bounds how long a busy enumeration waits for a pass.
	defaultMaxWait = time.Minute
	// passTimeout bounds one pass over every in-scope organization.
	passTimeout = 3 * time.Minute
)

// signalTypes are the asset types whose arrival can create or complete an
// ownership signal.
var signalTypes = []oam.AssetType{oam.Organization, oam.Person, oam.ContactRecord, oam.DomainRecord,
	oam.IPNetRecord, oam.AutnumRecord, oam.FQDN, oam.IPAddress, oam.TLSCertificate}

type plugin struct {
	name    string
	log     *slog.Logger
	lookup  func(string) (string, bool)
	quiet   time.Duration
	maxWait time.Duration
	// mergeCheck is how often the merge watcher checks for drained work;
	// zero turns duplicate merging off.
	mergeCheck time.Duration
	// othersWait bounds how long auto mode waits for other sessions before
	// recording proposals without applying them.
	othersWait time.Duration
	// mergeQuiet is how long the organizations of a strong merge proposal
	// must go unwritten before it is applied mid-run (quietMerges).
	mergeQuiet time.Duration
	// mergeMu lets one session's merge pass run at a time.
	mergeMu  sync.Mutex
	mu       sync.Mutex
	sessions map[uuid.UUID]*tracker
}

// NewAttribution returns the ownership attribution plugin.
func NewAttribution() et.Plugin {
	return &plugin{name: "AI-Attribution", lookup: os.LookupEnv, quiet: defaultQuiet, maxWait: defaultMaxWait,
		mergeCheck: defaultMergeCheck, othersWait: defaultOthersWait, mergeQuiet: defaultMergeQuiet,
		sessions: map[uuid.UUID]*tracker{}}
}

func (p *plugin) Name() string {
	return p.name
}

func (p *plugin) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)
	for _, t := range signalTypes {
		if err := r.RegisterHandler(&et.Handler{
			Plugin:       p,
			Name:         p.name + "-" + string(t) + "-Handler",
			Position:     50,
			MaxInstances: support.MinHandlerInstances,
			Transforms:   []string{string(oam.Organization)},
			EventType:    t,
			Callback:     p.check,
		}); err != nil {
			return err
		}
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *plugin) Stop() {
	p.log.Info("Plugin stopped")
}

// check notes an arriving signal; the pass itself runs in the background.
func (p *plugin) check(e *et.Event) error {
	if e == nil || e.Session == nil || e.Entity == nil || e.Entity.Asset == nil {
		return nil
	}
	if t := p.tracker(e.Session); t != nil {
		t.touch(e.Entity)
	}

	return nil
}

// tracker returns the session's tracker, or nil when attribution is off.
func (p *plugin) tracker(sess et.Session) *tracker {
	p.mu.Lock()
	defer p.mu.Unlock()

	for id, t := range p.sessions {
		if t.sess.Done() && !t.busy() {
			delete(p.sessions, id)
		}
	}
	if t, ok := p.sessions[sess.ID()]; ok {
		return t.enabled()
	}

	mode, _, err := sess.Config().AIAttribution(p.lookup)
	t := &tracker{p: p, sess: sess, mode: mode, canary: sess.Config().AIAttributionCanaryEvery(p.lookup),
		orgs: map[string]*dbt.Entity{}, allOrgs: map[string]*dbt.Entity{}, dupProcessed: map[string]struct{}{},
		allPersons: map[string]*dbt.Entity{}, personProcessed: map[string]struct{}{}}
	switch {
	case err != nil:
		sess.Log().Error(fmt.Sprintf("AI attribution is off: %v", err))
		t.mode = config.AttributionOff
	case mode != config.AttributionOff:
		t.journal = support.ReviewJournal(sess, p.lookup)
		model, err := ai.OwnershipKind.LoadFor(t.journal)
		if err != nil {
			sess.Log().Error(fmt.Sprintf("AI attribution uses its rules: %v", err))
		} else if model != nil {
			sess.Log().Info(fmt.Sprintf("AI attribution decides with ownership model %s", model.ModelID))
		}

		t.model = model
		if p.mergeCheck > 0 {
			// Counted before the watcher starts, so the session cannot be
			// reported finished in between.
			sess.Stats().AddBackground(1)
			go t.watchMerges()
		}
	}

	p.sessions[sess.ID()] = t
	return t.enabled()
}

// tracker schedules attribution passes for one session.
type tracker struct {
	p       *plugin
	sess    et.Session
	mode    string
	journal *review.Journal
	// model is the ownership model trained from review decisions, if any.
	model *classify.LinearModel

	mu sync.Mutex
	// orgs are the in-scope organizations this session touched; they seed the
	// ownership-attribution pass.
	orgs map[string]*dbt.Entity
	// allOrgs are every organization this session touched, in scope or not;
	// they seed the duplicate search, since the enumeration created or
	// re-touched them and so their duplicates are ours to raise.
	allOrgs map[string]*dbt.Entity
	// dupProcessed are the organizations the incremental duplicate/identity
	// pass has already compared, so each debounced pass does only the orgs
	// touched since the last one and proposals accumulate mid-run without
	// re-scanning what was already raised.
	dupProcessed map[string]struct{}
	// allPersons are every person this session touched; they seed the
	// person-duplicate search. personProcessed is its incremental cursor.
	allPersons      map[string]*dbt.Entity
	personProcessed map[string]struct{}
	// counted is the adapter the passes read through, counting its reads for
	// the log, and lasting keeps what they read from one pass to the next.
	counted oamrepo.Adapter
	lasting *graph.LastingCache
	// passes counts the passes; every canary-th one also searches each
	// organization without the lasting cache and compares
	// (options.ai.attribution_canary_every). Zero never does.
	passes  int
	canary  int
	gen     uint64
	pending bool
	first   time.Time
	last    time.Time
}

func (t *tracker) enabled() *tracker {
	if t.mode == config.AttributionOff {
		return nil
	}

	return t
}

func (t *tracker) busy() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.pending
}

// touch records a signal and schedules a pass. A pending pass counts as
// session work, so the enumeration is not reported finished before it runs.
func (t *tracker) touch(ent *dbt.Entity) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch ent.Asset.AssetType() {
	case oam.Organization:
		// Seed the duplicate search from every organization the session
		// touches, in scope or not: the enumeration caused the write, so its
		// duplicates are ours to raise. Scope still gates ownership
		// attribution below, which is about the target's own organizations.
		t.allOrgs[ent.ID] = ent
		if _, conf := t.sess.Scope().IsAssetInScope(ent.Asset, 0); conf > 0 {
			t.orgs[ent.ID] = ent
		}
	case oam.Person:
		// Seed the person-duplicate search from every person the run touched.
		t.allPersons[ent.ID] = ent
	}
	if len(t.orgs) == 0 {
		return
	}

	now := time.Now()
	t.gen++
	t.last = now
	if !t.pending {
		t.pending, t.first = true, now
		t.sess.Stats().AddBackground(1)
		go t.run()
	}
}

// run waits for the signals to settle, then runs passes until no new signal
// arrived during the last one.
func (t *tracker) run() {
	for {
		t.mu.Lock()
		wait := min(time.Until(t.last.Add(t.p.quiet)), time.Until(t.first.Add(t.p.maxWait)))
		t.mu.Unlock()
		if wait > 0 {
			select {
			case <-t.sess.Ctx().Done():
				t.finish()
				return
			case <-time.After(wait):
			}

			continue
		}
		if t.sess.Done() {
			t.finish()
			return
		}

		t.mu.Lock()
		gen := t.gen
		orgs := make([]*dbt.Entity, 0, len(t.orgs))
		for _, o := range t.orgs {
			orgs = append(orgs, o)
		}

		t.mu.Unlock()

		t.pass(orgs)

		t.mu.Lock()
		if t.gen == gen {
			t.pending = false
			t.sess.Stats().AddBackground(-1)
			t.mu.Unlock()
			return
		}

		t.first = time.Now()
		t.mu.Unlock()
	}
}

func (t *tracker) finish() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.pending {
		t.pending = false
		t.sess.Stats().AddBackground(-1)
	}
}

// pass attributes each in-scope organization's ownership gaps.
func (t *tracker) pass(orgs []*dbt.Entity) {
	ctx, cancel := context.WithTimeout(t.sess.Ctx(), passTimeout)
	defer cancel()

	adapter := oamrepo.New(t.sess.DB(), t.sess.Config())
	if t.lasting == nil {
		t.counted = adapter
		t.counted.Stats = &oamrepo.ReadStats{}
		t.lasting = graph.NewLastingCache(t.counted)
	}

	// a duplicate waiting for its merge is not searched on its own
	waiting := t.quietMerges(ctx, adapter)
	t.passes++
	canary := t.canary > 0 && t.passes%t.canary == 0
	for _, o := range orgs {
		if ctx.Err() != nil {
			return
		}
		if _, wait := waiting[o.ID]; wait {
			continue
		}

		// each organization's reads are counted on their own, for the log,
		// and read after the cache has dropped what changed since the last
		// search, the writes this pass made included
		t.counted.Stats.Reset()
		start := time.Now()
		g, err := t.lasting.Refresh(ctx)
		if err != nil && !errors.Is(err, graph.ErrUnsupported) {
			t.sess.Log().Warn("AI attribution reads without its lasting cache", "error", err.Error())
		}

		org, err := g.GetAsset(ctx, o.ID)
		if err != nil {
			continue
		}

		var want *lens.OwnershipGapReport
		if canary {
			want = t.uncachedSearch(ctx, adapter, org)
		}

		policy := review.AttributionPolicy{Mode: t.mode, Anchors: t.sess.Config().Domains()}
		if t.model != nil {
			policy.Model = ai.OwnershipModel{LinearModel: t.model}
		}

		res, err := review.AttributeOwnership(ctx, g, oamrepo.Catalog{}, org, t.counted, t.journal, policy)
		if err != nil {
			t.sess.Log().Error(fmt.Sprintf("AI attribution for %s: %v", graph.AssetLabel(org), err))
		} else if want != nil {
			t.compareCanary(org, *want, res.Report)
		}
		reads, took, byMethod := t.counted.Stats.Summary()
		t.sess.Log().Info("AI attribution pass", "organization", graph.AssetLabel(org),
			"footprint", res.Report.Footprint, "candidates", len(res.Report.Candidates),
			"lens_reads", res.Report.Reads, "db_reads", reads, "db_took", took.Round(time.Millisecond).String(),
			"db_reads_by_method", byMethod, "took", time.Since(start).Round(time.Millisecond).String())
		if res.Unanchored {
			continue
		}
		for _, a := range res.Applied {
			if !a.Existed {
				t.sess.Log().Info(fmt.Sprintf("AI attribution recorded %s %s as owned by %s (confidence %d, proposal %s)",
					a.Proposal.AssetType, a.Proposal.Asset, a.Proposal.Owner, review.ProposalConfidence(a.Proposal),
					a.Proposal.ID))
			}

			t.widenScope(ctx, a.Gains)
		}
		if len(res.Queued) > 0 {
			why := ""
			if res.Partial {
				why = fmt.Sprintf(" (the footprint was cut short: %s, so nothing was applied)", res.Report.Reason)
			}
			t.sess.Log().Info(fmt.Sprintf("AI attribution left %d ownership proposal(s) for %s in %s for review%s",
				len(res.Queued), graph.AssetLabel(org), t.journal.Path, why))
		}
	}

	// Raise duplicate and identity proposals for the organizations touched
	// since the last pass, so they accumulate for review mid-run instead of
	// only at drain. Record-only: the next pass's quietMerges applies the
	// strong ones whose organizations have gone unwritten.
	t.incrementalProposals(ctx, adapter)
	t.incrementalPersonProposals(ctx, adapter)
}

// widenScope asks the session's scope to admit the assets an attribution
// brought under an in-scope organization.
func (t *tracker) widenScope(ctx context.Context, gains []graph.Asset) {
	for _, g := range gains {
		ent, err := t.sess.DB().FindEntityById(ctx, g.ID)
		if err != nil || ent == nil || ent.Asset == nil {
			continue
		}
		_, _ = t.sess.Scope().Admit(&et.AdmissionRequest{Entity: ent, Via: t.p.name,
			Evidence: []et.AdmissionEvidence{{Signal: et.SignalOwnershipAttribution, Strength: et.StrengthStrong}}})
	}
}

// uncachedSearch searches org's ownership gaps with a cache for this search
// alone, for the canary to compare with the lasting cache's search.
func (t *tracker) uncachedSearch(ctx context.Context, adapter oamrepo.Adapter,
	org graph.Asset) *lens.OwnershipGapReport {
	report, err := lens.SearchOwnershipGaps(ctx, graph.Cached(adapter), oamrepo.Catalog{}, org)
	if err != nil {
		t.sess.Log().Warn("AI attribution canary search failed", "organization", graph.AssetLabel(org),
			"error", err.Error())
		return nil
	}

	return &report
}

// compareCanary warns when the lasting cache's search found other than the
// search without it. Writes other handlers made between the two searches
// can also explain a difference.
func (t *tracker) compareCanary(org graph.Asset, want, got lens.OwnershipGapReport) {
	want.Reads, got.Reads = 0, 0
	if reflect.DeepEqual(want, got) {
		t.sess.Log().Info("AI attribution canary matched", "organization", graph.AssetLabel(org))
		return
	}

	t.sess.Log().Warn("AI attribution canary found the lasting cache's search differs", "organization",
		graph.AssetLabel(org), "footprint", got.Footprint, "footprint_uncached", want.Footprint,
		"candidates", len(got.Candidates), "candidates_uncached", len(want.Candidates),
		"truncated", got.Truncated, "truncated_uncached", want.Truncated)
}
