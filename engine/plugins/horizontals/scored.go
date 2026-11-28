// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
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
// person. Scope is never grown when the expansion policy admits nothing. It runs at most once per
// organization per TTL window.
func (h *horizPlugin) expandRelatedDomains(e *et.Event, orgEnt *dbt.Entity) {
	sess := e.Session
	if !sess.Config().Widens() || orgEnt == nil {
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

	adapter := oamrepo.New(sess.DB(), sess.Config())
	report, err := lens.FindRelatedDomains(ctx, adapter, oamrepo.Catalog{}, orgEnt.ID)
	if err != nil {
		sess.Log().Error(err.Error(), slog.Group("plugin", "name", h.name))
		return
	}

	expand, needsReview := lens.HorizontalExpansion(report)
	j := h.journalFor(sess)
	approved, declined := personScopeDecisions(j)
	for _, d := range expand {
		id := review.ScopeExpansionID(orgEnt.ID, "", d.Domain)
		if declined[id] {
			continue
		}
		if !h.widenScopeToDomain(ctx, sess, d.Domain, d.Confidence,
			signalEvidence(d.SignalIDs, et.StrengthStrong, d.ContributedSignals...)...) {
			continue
		}
		sess.Log().Info("horizontal correlation widened scope",
			"domain", d.Domain, "org", report.Org, "confidence", d.Confidence,
			slog.Group("plugin", "name", h.name))
		if _, ok := approved[id]; !ok {
			h.recordExpansion(j, orgEnt.ID, report.Org, d, review.ProposalApplied, review.AutomaticReviewer, 0, nil)
		}
	}
	// Corroboration-only candidates: a person's approval or a trained model may
	// promote one to a scope expansion; otherwise it is proposed for a person,
	// never auto-added.
	scorer := h.horizontalScorer(sess)
	for _, d := range needsReview {
		id := review.ScopeExpansionID(orgEnt.ID, "", d.Domain)
		if declined[id] {
			continue
		}
		if e, ok := approved[id]; ok {
			if h.widenScopeToDomain(ctx, sess, d.Domain, d.Confidence,
				append(signalEvidence(d.SignalIDs, et.StrengthSupporting), reviewApproval(e))...) {
				sess.Log().Info("horizontal correlation widened scope (approved by "+e.Reviewer+")",
					"domain", d.Domain, "org", report.Org, slog.Group("plugin", "name", h.name))
			}
			continue
		}
		if scorer != nil {
			if prob, perr := scorer.Probability(d.SignalIDs, d.Confidence); perr == nil && prob >= scorer.Threshold() {
				ev := append(signalEvidence(d.SignalIDs, et.StrengthSupporting), et.AdmissionEvidence{
					Signal: "horizontal-model", Strength: et.StrengthStrong,
					Detail: fmt.Sprintf("model %s: probability %.2f", scorer.ModelName(), prob)})
				if h.widenScopeToDomain(ctx, sess, d.Domain, int(prob*100), ev...) {
					sess.Log().Info("horizontal correlation widened scope (model)",
						"domain", d.Domain, "org", report.Org, "probability", prob,
						slog.Group("plugin", "name", h.name))
					// An amass-ai-prefixed reviewer marks this an automatic
					// decision, so the reevaluation sweep can reconsider it;
					// "classifier" keeps it apart from the main model's.
					h.recordExpansion(j, orgEnt.ID, report.Org, d, review.ProposalApplied,
						fmt.Sprintf("amass-ai (classifier %s)", scorer.ModelName()), int(prob*100), nil)
				}
				continue
			}
		}
		h.decideOpenCandidate(ctx, sess, j, orgEnt, report.Org, d)
	}

	support.MarkAssetMonitored(sess, orgEnt, h.source)
}

// decideOpenCandidate sends a candidate with only supporting evidence to the
// scope for the organization. When the main model decides admissions, it
// decides this one on its own, and an admission is recorded as an automatic
// decision the user is told of and can undo; otherwise the candidate waits in
// the journal for a person.
func (h *horizPlugin) decideOpenCandidate(ctx context.Context, sess et.Session, j *review.Journal,
	orgEnt *dbt.Entity, org string, d lens.HorizontalDomain) {
	pending := func() { h.recordExpansion(j, orgEnt.ID, org, d, review.ProposalPending, "", 0, nil) }

	ents, err := sess.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1,
		dbt.ContentFilters{"name": strings.ToLower(strings.TrimSpace(d.Domain))})
	if err != nil || len(ents) != 1 {
		pending()
		return
	}
	if st := sess.Scope().Standing(ents[0].Asset); st == et.InScope || st == et.StandingAdmitted {
		return
	}

	req := &et.AdmissionRequest{Entity: ents[0], For: orgEnt, Via: h.name, Confidence: d.Confidence,
		Evidence: signalEvidence(d.SignalIDs, et.StrengthSupporting), Source: h.source,
		OnDecided: func(dec *et.AdmissionDecision) {
			if dec.Outcome != et.Admitted {
				// a model's answer goes with it, for the person and the
				// horizontal classifier
				h.recordExpansion(j, orgEnt.ID, org, d, review.ProposalPending, "", 0, scopeAdvice(dec))
				return
			}
			sess.Log().Info("horizontal correlation widened scope ("+dec.DecidedBy+")", "domain", d.Domain,
				"org", org, "confidence", dec.Confidence, "reason", dec.Rationale,
				slog.Group("plugin", "name", h.name))
			// An amass-ai-prefixed reviewer marks this an automatic decision,
			// so the reevaluation sweep can reconsider it.
			h.recordExpansion(j, orgEnt.ID, org, d, review.ProposalApplied, "amass-ai ("+dec.DecidedBy+")",
				dec.Confidence, nil)
		}}
	if _, err := sess.Scope().Admit(req); err != nil {
		pending()
	}
}

// scorerRefresh is how long a loaded horizontal model is used before the
// journal's newest is loaded again, so a model trained while the engine runs
// is picked up.
const scorerRefresh = 10 * time.Minute

// horizontalScorer returns the newest trained horizontal model for the
// session's review journal (kept in the database or beside the journal's
// file), loaded again every scorerRefresh, or nil when none is trained (then
// the weighted HorizontalScore alone decides).
func (h *horizPlugin) horizontalScorer(sess et.Session) *ai.HorizontalModel {
	j := support.ReviewJournal(sess, h.lookup)
	if j == nil {
		return nil
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.scorers[j]; ok && time.Since(c.at) < scorerRefresh {
		return c.model
	}

	m, err := ai.LoadHorizontalScorer(j)
	if err != nil {
		sess.Log().Error(fmt.Sprintf("horizontal model: %v", err), slog.Group("plugin", "name", h.name))
	} else if m != nil && (h.scorers[j].model == nil || h.scorers[j].model.ModelName() != m.ModelName()) {
		sess.Log().Info(fmt.Sprintf("horizontal expansion adjudicated by model %s", m.ModelName()),
			slog.Group("plugin", "name", h.name))
	}
	h.scorers[j] = scorerEntry{model: m, at: time.Now()}
	return m
}

// recordExpansion records a domain expansion; decided is the confidence of
// the decider that applied it (a model or the horizontal classifier), 0 for
// the rules or a pending one, and advice a model's answer on a pending one.
func (h *horizPlugin) recordExpansion(j *review.Journal, orgID, org string, d lens.HorizontalDomain,
	status, reviewer string, decided int, advice *review.ScopeAdvice) {
	if j == nil {
		return
	}
	_ = j.RecordScopeExpansion(review.ScopeExpansion{
		OrgID: orgID, Org: org, AssetType: review.DefaultScopeAssetType, Asset: d.Domain,
		Confidence: d.Confidence, Signals: d.Signals, SignalIDs: d.SignalIDs, Witness: d.Witness,
		Status: status, Reviewer: reviewer, DecidedConfidence: decided, Advice: advice,
	})
}

// scopeAdvice is a model's own answer on an admission it did not make, or
// nil when no model answered.
func scopeAdvice(dec *et.AdmissionDecision) *review.ScopeAdvice {
	var decision string
	switch dec.Conclusion {
	case et.Admitted:
		decision = review.ScopeAdviceAdmit
	case et.Rejected:
		decision = review.ScopeAdviceReject
	default:
		return nil
	}
	return &review.ScopeAdvice{Model: dec.DecidedBy, Decision: decision, Confidence: dec.Confidence,
		Reason: dec.Rationale}
}

// personScopeDecisions are the scope expansions a person approved, which a
// run that finds the candidate again admits on that approval, and those a
// person rejected or retracted, which no enumeration widens its scope to
// again.
func personScopeDecisions(j *review.Journal) (map[string]review.ScopeExpansion, map[string]bool) {
	if j == nil {
		return nil, nil
	}
	approved, _ := j.ApprovedScopeExpansions()
	declined, _ := j.DeclinedScopeExpansions()
	return approved, declined
}

// reviewApproval is the evidence a person's approval of an expansion gives.
func reviewApproval(e review.ScopeExpansion) et.AdmissionEvidence {
	return et.AdmissionEvidence{Signal: "review-approved", Strength: et.StrengthStrong,
		Detail: "approved in review by " + e.Reviewer}
}

// signalEvidence is the evidence a scored candidate carries: its signals, at
// the strength its group gives them (an expansion's are strong, a candidate
// left for review has only supporting ones). A signal in contributed, which
// rests on assistants' contributions, is supporting either way.
func signalEvidence(ids []string, strength string, contributed ...string) []et.AdmissionEvidence {
	ev := make([]et.AdmissionEvidence, 0, len(ids))
	for _, id := range ids {
		s := strength
		if slices.Contains(contributed, id) {
			s = et.StrengthSupporting
		}
		ev = append(ev, et.AdmissionEvidence{Signal: id, Strength: s})
	}
	return ev
}

// widenScopeToDomain asks the scope to admit the registered domain's stored
// FQDN on the evidence. It reports whether the domain was newly admitted
// (false when it is unknown, already in scope, or not admitted).
func (h *horizPlugin) widenScopeToDomain(ctx context.Context, sess et.Session, domain string, conf int,
	ev ...et.AdmissionEvidence) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}

	ents, err := sess.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{"name": domain})
	if err != nil || len(ents) != 1 {
		return false
	}
	return h.widen(sess, ents[0], conf, ev...)
}

// expandRelatedInfrastructure is the scored replacement for the single-signal
// netblock/AS expansion the handlers used to do. For an in-scope organization it
// scores the netblocks and autonomous systems the infrastructure signals tie to
// it (internal/lens: RIR netblock/AS registrant, and prefixes the org's AS
// announces, with privacy-proxy registrants excluded), adds the strongly-
// supported ones to scope, and records every decision in the review journal so
// it is auditable and reconsiderable by the same reevaluation sweep. Announced-
// only (corroboration) candidates are left as pending proposals. Scope is never
// grown when the expansion policy admits nothing. It runs at most once per organization per TTL
// window, under its own source so it does not collide with the domain pass.
func (h *horizPlugin) expandRelatedInfrastructure(e *et.Event, orgEnt *dbt.Entity) {
	sess := e.Session
	if !sess.Config().Widens() || orgEnt == nil {
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

	adapter := oamrepo.New(sess.DB(), sess.Config())
	report, err := lens.FindRelatedInfrastructure(ctx, adapter, orgEnt.ID)
	if err != nil {
		sess.Log().Error(err.Error(), slog.Group("plugin", "name", h.name))
		return
	}

	expand, needsReview := lens.InfrastructureExpansion(report)
	j := h.journalFor(sess)
	approved, declined := personScopeDecisions(j)
	for _, a := range expand {
		id := review.ScopeExpansionID(orgEnt.ID, a.AssetType, a.Asset)
		if declined[id] {
			continue
		}
		if !h.widenScopeToAsset(ctx, sess, a.AssetType, a.Asset, a.Confidence,
			signalEvidence(a.SignalIDs, et.StrengthStrong, a.ContributedSignals...)...) {
			continue
		}
		sess.Log().Info("infrastructure correlation widened scope",
			"type", a.AssetType, "asset", a.Asset, "org", report.Org, "confidence", a.Confidence,
			slog.Group("plugin", "name", h.name))
		if _, ok := approved[id]; !ok {
			h.recordInfraExpansion(j, orgEnt.ID, report.Org, a, review.ProposalApplied, review.AutomaticReviewer)
		}
	}
	for _, a := range needsReview {
		id := review.ScopeExpansionID(orgEnt.ID, a.AssetType, a.Asset)
		if declined[id] {
			continue
		}
		if e, ok := approved[id]; ok {
			if h.widenScopeToAsset(ctx, sess, a.AssetType, a.Asset, a.Confidence,
				append(signalEvidence(a.SignalIDs, et.StrengthSupporting), reviewApproval(e))...) {
				sess.Log().Info("infrastructure correlation widened scope (approved by "+e.Reviewer+")",
					"type", a.AssetType, "asset", a.Asset, "org", report.Org, slog.Group("plugin", "name", h.name))
			}
			continue
		}
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

// widenScopeToAsset asks the scope to admit a netblock (by CIDR) or
// autonomous system (by number) on the evidence, as widenScopeToDomain does.
// It reports whether the asset was newly admitted.
func (h *horizPlugin) widenScopeToAsset(ctx context.Context, sess et.Session, assetType, asset string, conf int,
	ev ...et.AdmissionEvidence) bool {
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
	if !h.widen(sess, ent, conf, ev...) {
		return false
	}
	return true
}

// journalFor returns the review journal automatic attribution uses, so scored
// scope expansions are recorded alongside the other AI decisions, or nil when
// attribution (and therefore the journal) is off.
func (h *horizPlugin) journalFor(sess et.Session) *review.Journal {
	return support.ReviewJournal(sess, h.lookup)
}
