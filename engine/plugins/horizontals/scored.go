// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// expandRelatedDomains is the scored replacement for the single-signal domain
// expansion the handlers used to do. For an in-scope organization it scores the
// registered domains the horizontal signals tie to it (internal/lens: shared
// registrant, certificate subject, name server, official website, with privacy-
// proxy and provider/CDN values excluded and corroborating signals combined),
// adds the strongly-supported ones to scope, and records every decision in the
// review journal so it is auditable and can be reconsidered (the reevaluation
// sweep). Candidates with only corroboration are left as pending proposals for a
// person. Scope is never grown when the run is Rigid. It runs at most once per
// organization per TTL window.
func (h *horizPlugin) expandRelatedDomains(e *et.Event, orgEnt *dbt.Entity) {
	sess := e.Session
	if sess.Config().Rigid || orgEnt == nil {
		return
	}
	if _, ok := orgEnt.Asset.(*oamorg.Organization); !ok {
		return
	}

	since, err := support.TTLStartTime(sess.Config(), string(oam.Organization), string(oam.FQDN), h.name)
	if err != nil {
		return
	}
	if support.AssetMonitoredWithinTTL(sess, orgEnt, h.source, since) {
		return
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), time.Minute)
	defer cancel()

	adapter := oamrepo.Adapter{Repo: sess.DB(), Neo4jDatabase: oamrepo.Neo4jDatabaseName(sess.Config())}
	report, err := lens.FindRelatedDomains(ctx, adapter, orgEnt.ID)
	if err != nil {
		sess.Log().Error(err.Error(), slog.Group("plugin", "name", h.name))
		return
	}

	expand, needsReview := lens.HorizontalExpansion(report)
	j := h.journalFor(sess)
	for _, d := range expand {
		if !h.widenScopeToDomain(ctx, sess, d.Domain) {
			continue
		}
		sess.Log().Info("horizontal correlation widened scope",
			"domain", d.Domain, "org", report.Org, "confidence", d.Confidence,
			slog.Group("plugin", "name", h.name))
		h.recordExpansion(j, orgEnt.ID, report.Org, d, review.ProposalApplied, review.AutomaticReviewer)
	}
	// Corroboration-only candidates: a trained model may promote one to a scope
	// expansion; otherwise it is proposed for a person, never auto-added.
	scorer := h.horizontalScorer(sess)
	for _, d := range needsReview {
		if scorer != nil {
			if prob, perr := scorer.Probability(d.SignalIDs, d.Confidence); perr == nil && prob >= scorer.Threshold() {
				if h.widenScopeToDomain(ctx, sess, d.Domain) {
					sess.Log().Info("horizontal correlation widened scope (model)",
						"domain", d.Domain, "org", report.Org, "probability", prob,
						slog.Group("plugin", "name", h.name))
					// An amass-ai-prefixed reviewer marks this an automatic
					// decision, so the reevaluation sweep can reconsider it.
					h.recordExpansion(j, orgEnt.ID, report.Org, d, review.ProposalApplied,
						fmt.Sprintf("amass-ai (model %s)", scorer.ModelName()))
				}
				continue
			}
		}
		h.recordExpansion(j, orgEnt.ID, report.Org, d, review.ProposalPending, "")
	}

	support.MarkAssetMonitored(sess, orgEnt, h.source)
}

// horizontalScorer returns the trained horizontal model beside the session's
// review journal, loaded once per path, or nil when none is trained (then the
// weighted HorizontalScore alone decides).
func (h *horizPlugin) horizontalScorer(sess et.Session) *ai.HorizontalModel {
	_, path, err := sess.Config().AIAttribution(h.lookup)
	if err != nil || path == "" {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.scorerLoaded[path] {
		return h.scorers[path]
	}

	m, err := ai.LoadHorizontalScorer(path)
	if err != nil {
		sess.Log().Error(fmt.Sprintf("horizontal model: %v", err), slog.Group("plugin", "name", h.name))
	} else if m != nil {
		sess.Log().Info(fmt.Sprintf("horizontal expansion adjudicated by model %s", m.ModelName()),
			slog.Group("plugin", "name", h.name))
	}
	h.scorerLoaded[path] = true
	h.scorers[path] = m

	return m
}

func (h *horizPlugin) recordExpansion(j *review.Journal, orgID, org string, d lens.HorizontalDomain,
	status, reviewer string) {
	if j == nil {
		return
	}
	_ = j.RecordScopeExpansion(review.ScopeExpansion{
		OrgID: orgID, Org: org, AssetType: review.DefaultScopeAssetType, Asset: d.Domain,
		Confidence: d.Confidence, Signals: d.Signals, SignalIDs: d.SignalIDs, Witness: d.Witness,
		Status: status, Reviewer: reviewer,
	})
}

// widenScopeToDomain adds the registered domain's FQDN to the session scope and
// enqueues it, mirroring addToScopeAndEnqueue. It reports whether the domain was
// newly added (false when it is unknown or already in scope).
func (h *horizPlugin) widenScopeToDomain(ctx context.Context, sess et.Session, domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	ents, err := sess.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{"name": domain})
	if err != nil || len(ents) != 1 {
		return false
	}
	ent := ents[0]
	if !sess.Scope().Add(ent.Asset) {
		return false
	}
	if econf := h.confidence(sess, ent.Asset.AssetType()); econf > 0 {
		if a, c := sess.Scope().IsAssetInScope(ent.Asset, econf); c >= econf && strings.EqualFold(a.Key(),
			ent.Asset.Key()) {
			_ = sess.Backlog().Enqueue(ent)
		}
	}

	return true
}

// expandRelatedInfrastructure is the scored replacement for the single-signal
// netblock/AS expansion the handlers used to do. For an in-scope organization it
// scores the netblocks and autonomous systems the infrastructure signals tie to
// it (internal/lens: RIR netblock/AS registrant, and prefixes the org's AS
// announces, with privacy-proxy registrants excluded), adds the strongly-
// supported ones to scope, and records every decision in the review journal so
// it is auditable and reconsiderable by the same reevaluation sweep. Announced-
// only (corroboration) candidates are left as pending proposals. Scope is never
// grown when the run is Rigid. It runs at most once per organization per TTL
// window, under its own source so it does not collide with the domain pass.
func (h *horizPlugin) expandRelatedInfrastructure(e *et.Event, orgEnt *dbt.Entity) {
	sess := e.Session
	if sess.Config().Rigid || orgEnt == nil {
		return
	}
	if _, ok := orgEnt.Asset.(*oamorg.Organization); !ok {
		return
	}

	since, err := support.TTLStartTime(sess.Config(), string(oam.Organization), string(oam.Netblock), h.name)
	if err != nil {
		return
	}
	if support.AssetMonitoredWithinTTL(sess, orgEnt, h.infraSource, since) {
		return
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), time.Minute)
	defer cancel()

	adapter := oamrepo.Adapter{Repo: sess.DB(), Neo4jDatabase: oamrepo.Neo4jDatabaseName(sess.Config())}
	report, err := lens.FindRelatedInfrastructure(ctx, adapter, orgEnt.ID)
	if err != nil {
		sess.Log().Error(err.Error(), slog.Group("plugin", "name", h.name))
		return
	}

	expand, needsReview := lens.InfrastructureExpansion(report)
	j := h.journalFor(sess)
	for _, a := range expand {
		if !h.widenScopeToAsset(ctx, sess, a.AssetType, a.Asset) {
			continue
		}
		sess.Log().Info("infrastructure correlation widened scope",
			"type", a.AssetType, "asset", a.Asset, "org", report.Org, "confidence", a.Confidence,
			slog.Group("plugin", "name", h.name))
		h.recordInfraExpansion(j, orgEnt.ID, report.Org, a, review.ProposalApplied, review.AutomaticReviewer)
	}
	for _, a := range needsReview {
		h.recordInfraExpansion(j, orgEnt.ID, report.Org, a, review.ProposalPending, "")
	}

	support.MarkAssetMonitored(sess, orgEnt, h.infraSource)
}

func (h *horizPlugin) recordInfraExpansion(j *review.Journal, orgID, org string, a lens.InfrastructureAsset,
	status, reviewer string) {
	if j == nil {
		return
	}
	_ = j.RecordScopeExpansion(review.ScopeExpansion{
		OrgID: orgID, Org: org, AssetType: a.AssetType, Asset: a.Asset,
		Confidence: a.Confidence, Signals: a.Signals, SignalIDs: a.SignalIDs, Witness: a.Witness,
		Status: status, Reviewer: reviewer,
	})
}

// widenScopeToAsset adds a netblock (by CIDR) or autonomous system (by number)
// to the session scope and enqueues it, mirroring widenScopeToDomain. It reports
// whether the asset was newly added (false when unknown or already in scope).
func (h *horizPlugin) widenScopeToAsset(ctx context.Context, sess et.Session, assetType, asset string) bool {
	asset = strings.ToLower(strings.TrimSpace(asset))
	if asset == "" {
		return false
	}

	var otype oam.AssetType
	var filter dbt.ContentFilters
	switch assetType {
	case "Netblock":
		otype, filter = oam.Netblock, dbt.ContentFilters{"cidr": asset}
	case "AutonomousSystem":
		n, err := strconv.Atoi(asset)
		if err != nil {
			return false
		}
		otype, filter = oam.AutonomousSystem, dbt.ContentFilters{"number": n}
	default:
		return false
	}

	ents, err := sess.DB().FindEntitiesByContent(ctx, otype, time.Time{}, 1, filter)
	if err != nil || len(ents) != 1 {
		return false
	}
	ent := ents[0]
	if !sess.Scope().Add(ent.Asset) {
		return false
	}
	// Seed the sweep budget for a newly owned netblock, so the neighborhood
	// sweep of its addresses is bounded (and refunded by evidence) rather than
	// probing a large owned network wholesale. Keyed on the canonical CIDR to
	// match horaddr.inOwnedNetblock.
	if nb, ok := ent.Asset.(*oamnet.Netblock); ok {
		support.SweepBudgetFor(sess.ID().String()).Seed(nb.CIDR.String(), support.SweepSeedWindow)
	}
	if econf := h.confidence(sess, ent.Asset.AssetType()); econf > 0 {
		if a, c := sess.Scope().IsAssetInScope(ent.Asset, econf); c >= econf && strings.EqualFold(a.Key(),
			ent.Asset.Key()) {
			_ = sess.Backlog().Enqueue(ent)
		}
	}

	return true
}

// journalFor returns the review journal automatic attribution uses, so scored
// scope expansions are recorded alongside the other AI decisions, or nil when
// attribution (and therefore the journal) is off.
func (h *horizPlugin) journalFor(sess et.Session) *review.Journal {
	mode, path, err := sess.Config().AIAttribution(h.lookup)
	if err != nil || mode == config.AttributionOff || path == "" {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	j, ok := h.journals[path]
	if !ok {
		j = &review.Journal{Path: path}
		h.journals[path] = j
	}

	return j
}
