// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package attribution records ownership the evidence supports while an
// enumeration runs. When assets that carry ownership signals arrive, it
// finds the ownership gaps of the session's in-scope organizations, writes
// the strong proposals with an amass-ai source, widens the scope the same
// way the Horizontals plugin does, and leaves the rest in the review
// journal. It needs no model.
package attribution

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/ai/oamrepo"
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
var signalTypes = []oam.AssetType{oam.Organization, oam.ContactRecord, oam.DomainRecord, oam.IPNetRecord,
	oam.AutnumRecord, oam.FQDN, oam.IPAddress, oam.TLSCertificate}

type plugin struct {
	name     string
	log      *slog.Logger
	lookup   func(string) (string, bool)
	quiet    time.Duration
	maxWait  time.Duration
	mu       sync.Mutex
	sessions map[uuid.UUID]*tracker
	journals map[string]*ai.Journal
}

// NewAttribution returns the ownership attribution plugin.
func NewAttribution() et.Plugin {
	return &plugin{name: "AI-Attribution", lookup: os.LookupEnv, quiet: defaultQuiet, maxWait: defaultMaxWait,
		sessions: map[uuid.UUID]*tracker{}, journals: map[string]*ai.Journal{}}
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

	mode, path, err := sess.Config().AIAttribution(p.lookup)
	t := &tracker{p: p, sess: sess, mode: mode, orgs: map[string]*dbt.Entity{}}
	switch {
	case err != nil:
		sess.Log().Error(fmt.Sprintf("AI attribution is off: %v", err))
		t.mode = config.AttributionOff
	case mode != config.AttributionOff:
		j, ok := p.journals[path]
		if !ok {
			j = &ai.Journal{Path: path}
			p.journals[path] = j
		}

		t.journal = j
		model, err := ai.LoadAttributionModel(ai.AttributionModelPath(path))
		if err != nil {
			sess.Log().Error(fmt.Sprintf("AI attribution uses its rules: %v", err))
		} else if model != nil {
			sess.Log().Info(fmt.Sprintf("AI attribution decides with ownership model %s", model.ModelID))
		}

		t.model = model
	}

	p.sessions[sess.ID()] = t
	return t.enabled()
}

// tracker schedules attribution passes for one session.
type tracker struct {
	p       *plugin
	sess    et.Session
	mode    string
	journal *ai.Journal
	// model is the ownership model trained from review decisions, if any.
	model *classify.LinearModel

	mu      sync.Mutex
	orgs    map[string]*dbt.Entity
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

	if ent.Asset.AssetType() == oam.Organization {
		if _, conf := t.sess.Scope().IsAssetInScope(ent.Asset, 0); conf > 0 {
			t.orgs[ent.ID] = ent
		}
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

	adapter := oamrepo.Adapter{Repo: t.sess.DB(), Neo4jDatabase: oamrepo.Neo4jDatabaseName(t.sess.Config())}
	for _, o := range orgs {
		if ctx.Err() != nil {
			return
		}

		org, err := adapter.GetAsset(ctx, o.ID)
		if err != nil {
			continue
		}

		res, err := ai.AttributeOwnership(ctx, adapter, oamrepo.Catalog{}, org, adapter, t.journal,
			ai.AttributionPolicy{Mode: t.mode, Model: t.model, Anchors: t.sess.Config().Domains()})
		if err != nil {
			t.sess.Log().Error(fmt.Sprintf("AI attribution for %s: %v", ai.AssetLabel(org), err))
		}
		if res.Unanchored {
			continue
		}
		for _, a := range res.Applied {
			if !a.Existed {
				t.sess.Log().Info(fmt.Sprintf("AI attribution recorded %s %s as owned by %s (confidence %d, proposal %s)",
					a.Proposal.AssetType, a.Proposal.Asset, a.Proposal.Owner, ai.ProposalConfidence(a.Proposal),
					a.Proposal.ID))
			}

			t.widenScope(ctx, a.Gains)
		}
		if len(res.Queued) > 0 {
			t.sess.Log().Info(fmt.Sprintf("AI attribution left %d ownership proposal(s) for %s in %s for review",
				len(res.Queued), ai.AssetLabel(org), t.journal.Path))
		}
	}
}

// widenScope adds the assets an attribution brought under an in-scope
// organization to the session scope, and queues them for another look when
// the configuration's confidence for their type allows it, as the
// Horizontals plugin does.
func (t *tracker) widenScope(ctx context.Context, gains []ai.Asset) {
	if t.sess.Config().Rigid {
		return
	}

	for _, g := range gains {
		ent, err := t.sess.DB().FindEntityById(ctx, g.ID)
		if err != nil || ent == nil || ent.Asset == nil || !t.sess.Scope().Add(ent.Asset) {
			continue
		}

		conf := t.confidence(ent.Asset.AssetType())
		if conf <= 0 {
			continue
		}
		if a, c := t.sess.Scope().IsAssetInScope(ent.Asset, conf); c >= conf && strings.EqualFold(a.Key(), ent.Asset.Key()) {
			_ = t.sess.Backlog().Enqueue(ent)
		}
	}
}

// confidence is the configured scope confidence for an asset type.
func (t *tracker) confidence(atype oam.AssetType) int {
	tstr := string(atype)
	if matches, err := t.sess.Config().CheckTransformations(tstr, tstr); err == nil && matches != nil {
		if conf := matches.Confidence(t.p.name); conf > 0 {
			return conf
		}
		if conf := matches.Confidence(tstr); conf > 0 {
			return conf
		}
	}

	return -1
}
