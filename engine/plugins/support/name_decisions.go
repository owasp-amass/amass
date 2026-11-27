// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeop "github.com/owasp-amass/open-asset-model/people"
)

const (
	// nameDecisionBudget bounds the asking of one name.
	nameDecisionBudget = 5 * time.Minute
	// NameKindApplyConfidence is the confidence a decider's answer needs to
	// be applied, under attribution auto; a lower one is kept as advice.
	NameKindApplyConfidence = 90
	// nameKindEvidenceMax bounds the facts about a record a question gives.
	nameKindEvidenceMax = 24
	// nameKindGroupPasses bounds how often one answer looks again for
	// proposals of its name recorded while it was being given.
	nameKindGroupPasses = 3
)

// nameDecisions asks the session's name decider, one name at a time, beside
// the pipeline.
var nameDecisions = NewBackgroundLane("name decision", nameDecisionBudget)

// askNameKind queues the name proposal p for the session's name decider, when
// it has one. One question is asked per name in a field (review.NameKindGroup):
// a name another proposal of the group already has an answer for takes that
// answer without asking, and an answer is given to every unanswered pending
// proposal of the group. With attribution auto, an answer naming a kind at
// NameKindApplyConfidence or above is applied as an automatic decision the
// user can retract; any other answer is kept on the proposals as advice for
// the person who decides them.
func askNameKind(sess et.Session, j *review.Journal, p review.NameKindProposal, plugin string) {
	d := sess.NameKinds()
	if d == nil {
		return
	}

	nameDecisions.Enqueue(sess, "nk|"+p.Group(), plugin, p.Name, func(ctx context.Context) {
		a, err := nameKindAnswer(ctx, sess, j, d, p)
		if err != nil {
			sess.Log().Info("name left for review: "+err.Error(), "name", p.Name, slog.Group("plugin", "name", plugin))
			return
		}

		// proposals of the name recorded while it was asked, whose own asks
		// the lane folded into this one, are answered too
		for range nameKindGroupPasses {
			group, err := j.UnansweredNameKindGroup(p)
			if err != nil {
				sess.Log().Warn("name answer not recorded: "+err.Error(), "name", p.Name,
					slog.Group("plugin", "name", plugin))
				return
			}
			if len(group) == 0 {
				return
			}
			for _, g := range group {
				answerNameKind(ctx, sess, j, g, a, plugin)
			}
		}
	})
}

// nameKindAnswered is an answer to a name proposal, from the decider or
// taken from another proposal of its group.
type nameKindAnswered struct {
	review.NameKindAdvice
	adviceOnly bool
}

// nameKindAnswer is the answer for p: another proposal of its group's, or
// else the decider's.
func nameKindAnswer(ctx context.Context, sess et.Session, j *review.Journal, d et.NameKindDecider,
	p review.NameKindProposal) (nameKindAnswered, error) {
	if prior, ok, err := j.NameKindGroupAnswer(p); err != nil {
		return nameKindAnswered{}, err
	} else if ok {
		return nameKindAnswered{NameKindAdvice: prior}, nil
	}

	q := nameKindQuestion(ctx, sess, p)
	a, err := d.Decide(ctx, q)
	if err != nil {
		return nameKindAnswered{}, err
	}
	by := a.DecidedBy
	if by == "" {
		by = d.Name()
	}
	var cites []string
	for _, c := range a.Cites {
		if c >= 1 && c <= len(q.Evidence) {
			cites = append(cites, q.Evidence[c-1])
		}
	}
	return nameKindAnswered{NameKindAdvice: review.NameKindAdvice{Model: by, Kind: a.Kind,
		Confidence: a.Confidence, Reason: a.Reason, Cites: cites}, adviceOnly: a.AdviceOnly}, nil
}

// answerNameKind applies a to the proposal p when attribution is auto and a
// is confident enough, and otherwise keeps it on p as advice.
func answerNameKind(ctx context.Context, sess et.Session, j *review.Journal, p review.NameKindProposal,
	a nameKindAnswered, plugin string) {
	by := a.Model
	if !strings.HasPrefix(by, review.InferenceSource) {
		by = review.InferenceSource + " (" + by + ")"
	}

	mode, _, _ := sess.Config().AIAttribution(os.LookupEnv)
	if mode == config.AttributionAuto && !a.adviceOnly && a.Kind != et.NameKindUnclear &&
		a.Confidence >= NameKindApplyConfidence {
		o, err := review.ApplyNameKind(ctx, oamrepo.Adapter{Repo: sess.DB()}, j, p.ID, a.Kind, by, a.Confidence,
			a.Reason)
		if err == nil {
			sess.Log().Info("name decided as "+a.Kind+" ("+a.Model+")", "name", p.Name, "entity", o.EntityID,
				"confidence", a.Confidence, "reason", a.Reason, slog.Group("plugin", "name", plugin))
			return
		}
		sess.Log().Warn("name decision not applied: "+err.Error(), "name", p.Name,
			slog.Group("plugin", "name", plugin))
	}

	advice := a.NameKindAdvice
	advice.ProposalID = p.ID
	if err := j.RecordNameKindAdvice(advice); err != nil {
		sess.Log().Warn("name advice not recorded: "+err.Error(), "name", p.Name,
			slog.Group("plugin", "name", plugin))
	}
}

// nameKindQuestion gathers, when the name is asked about, what is known
// around it: what the rules weighed, the record that gave it, the record's
// properties and what the record relates to.
func nameKindQuestion(ctx context.Context, sess et.Session, p review.NameKindProposal) *et.NameKindQuestion {
	q := &et.NameKindQuestion{Name: p.Name, Label: p.Label, RecordType: p.RecordType, Source: p.Source,
		Reasons: p.Reasons}
	for _, r := range p.Reasons {
		q.Evidence = append(q.Evidence, "the name rules found: "+r)
	}

	rec, err := sess.DB().FindEntityById(ctx, p.RecordID)
	if err != nil || rec == nil || rec.Asset == nil {
		return q
	}
	add := func(s string) bool {
		if len(q.Evidence) >= nameKindEvidenceMax {
			return false
		}
		q.Evidence = append(q.Evidence, s)
		return true
	}
	add(fmt.Sprintf("the record is the %s %s", rec.Asset.AssetType(), rec.Asset.Key()))

	if tags, err := sess.DB().FindEntityTags(ctx, rec, time.Time{}); err == nil {
		for _, t := range tags {
			if t == nil || t.Property == nil ||
				(t.Property.Name() == graph.UncertainNameProp && t.Property.Value() == p.Name) {
				continue
			}
			if !add(fmt.Sprintf("the record's %s is %q", t.Property.Name(), t.Property.Value())) {
				return q
			}
		}
	}

	if edges, err := sess.DB().OutgoingEdges(ctx, rec, time.Time{}); err == nil {
		for _, e := range edges {
			if e == nil || e.Relation == nil || e.ToEntity == nil {
				continue
			}
			to, err := sess.DB().FindEntityById(ctx, e.ToEntity.ID)
			if err != nil || to == nil || to.Asset == nil {
				continue
			}
			if !add(fmt.Sprintf("the record's %s is the %s %s", e.Relation.Label(), to.Asset.AssetType(),
				entityName(to))) {
				return q
			}
		}
	}
	return q
}

// entityName is how a fact names an entity: a person's or organization's
// name, or the asset's key.
func entityName(e *dbt.Entity) string {
	switch a := e.Asset.(type) {
	case *oampeop.Person:
		if a.FullName != "" {
			return fmt.Sprintf("%q", a.FullName)
		}
	case *oamorg.Organization:
		if a.Name != "" {
			return fmt.Sprintf("%q", a.Name)
		}
	}
	return e.Asset.Key()
}
