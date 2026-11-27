// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"math"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// The ownership model learns how much each kind of signal counts from
// review decisions in the journal, in place of the hand-set weights of
// scoreGap.
const (
	OwnershipTask           = "ownership_attribution"
	OwnershipFeatureVersion = "ownership-signals-v1"
)

// Ownership model bounds.
const (
	// minOwnershipThreshold is the lowest probability that may ever write.
	minOwnershipThreshold = 0.7
	// minOwnershipPrecision is the held-out precision a model needs before
	// it may decide automatic writes.
	minOwnershipPrecision = 0.9
)

// OwnershipKind is the ownership question: does an organization own the
// asset a proposal names.
var OwnershipKind = &AdjudicatorKind{
	Name:           "ownership",
	Question:       "whether an organization owns the asset an ownership proposal names",
	Task:           OwnershipTask,
	FeatureVersion: OwnershipFeatureVersion,
	File:           "attribution-model.json",
	Examples: func(j *review.Journal) ([]classify.LabeledExample, []string, error) {
		entries, err := j.OwnershipEntries()
		if err != nil {
			return nil, nil, err
		}
		rows, spec := OwnershipTrainingSet(entries)
		return rows, spec.Features, nil
	},
	MinExamples:  20,
	MinPrecision: minOwnershipPrecision,
	MinThreshold: minOwnershipThreshold,
	UsedBy:       "the engine's automatic attribution, `amass ai` and the MCP ownership-gap answers",
}

// OwnershipFeatures describes a proposal for the ownership model. Every
// value is in 0..1. Besides the totals per signal kind, each signal adds
// "kind:route", where route is the last word of how the signal was found
// (the shared value's type for identity, the controlled asset's type for
// hosting, the listing relationship for co-listing), and "signal:id" for
// its catalog entry. New signals and routes become features without code
// changes.
func OwnershipFeatures(p review.OwnershipProposal) map[string]float64 {
	f := map[string]float64{}
	count := map[string]int{}
	for _, s := range p.Signals {
		kind, via, _ := strings.Cut(s, " via ")
		count[kind]++
		if words := strings.Fields(via); len(words) > 0 {
			f[kind+":"+words[len(words)-1]] = 1
		}
	}
	for kind, n := range count {
		f[kind] = math.Min(float64(n), 2) / 2
	}

	for _, id := range p.SignalIDs {
		f["signal:"+id] = 1
	}

	f["kinds"] = math.Min(float64(len(count)), 3) / 3
	f["gains"] = math.Min(float64(len(p.Gains)), lens.GapMaxGains) / lens.GapMaxGains
	return f
}

// OwnershipLabel is a proposal's training label from its review outcome:
// a person's approval is positive; a rejection or retraction is negative.
// Pending proposals and every amass-ai decision (automatic writes, model
// decisions, re-checks) are not labels, so the model never learns from its
// own decisions.
func OwnershipLabel(e review.OwnershipEntry) (string, bool) {
	if e.Outcome == nil || strings.HasPrefix(e.Outcome.Reviewer, review.InferenceSource) {
		return "", false
	}

	switch e.Status {
	case review.ProposalApplied:
		return labelPositive, true
	case review.ProposalRejected, review.ProposalRetracted:
		return labelNegative, true
	}
	return "", false
}

// OwnershipTrainingSet turns reviewed journal entries into labeled examples
// and the feature list they use.
func OwnershipTrainingSet(entries []review.OwnershipEntry) ([]classify.LabeledExample, classify.LinearSpec) {
	var rows []classify.LabeledExample
	for _, e := range entries {
		// Departments are decided on other evidence than ownership signals.
		if e.Proposal.Kind != "" {
			continue
		}

		label, ok := OwnershipLabel(e)
		if !ok {
			continue
		}
		rows = append(rows, classify.LabeledExample{GroupID: e.Proposal.ID, Label: label,
			Features: OwnershipFeatures(e.Proposal)})
	}

	return rows, classify.LinearSpec{Task: OwnershipTask, FeatureVersion: OwnershipFeatureVersion,
		Features: featureNames(rows)}
}

// TrainOwnershipModel trains the ownership model on reviewed proposals
// (OwnershipKind.Train).
func TrainOwnershipModel(rows []classify.LabeledExample, spec classify.LinearSpec,
	modelID string) (*classify.LinearModel, classify.TrainingMetrics, error) {
	return OwnershipKind.Train(rows, spec.Features, modelID)
}

// LoadAttributionScorer loads the newest trained ownership model for the
// journal (OwnershipKind.LoadFor) as a review.OwnershipScorer, or returns a
// nil scorer (and no error) when there is no model, so callers can set it
// unconditionally and let the rules decide when none has been trained.
func LoadAttributionScorer(j *review.Journal) (review.OwnershipScorer, error) {
	m, err := OwnershipKind.LoadFor(j)
	if err != nil || m == nil {
		return nil, err
	}
	return OwnershipModel{LinearModel: m}, nil
}

// OwnershipModel decides automatic attribution with a trained ownership
// model.
type OwnershipModel struct{ *classify.LinearModel }

// ModelName implements OwnershipScorer.
func (m OwnershipModel) ModelName() string { return m.ModelID }

// Probability implements OwnershipScorer.
func (m OwnershipModel) Probability(p review.OwnershipProposal) (float64, error) {
	return ownershipProbability(m.LinearModel, p)
}

// Threshold implements OwnershipScorer.
func (m OwnershipModel) Threshold() float64 { return m.ReviewThreshold }

// ownershipProbability scores p with m, ignoring features m never saw.
func ownershipProbability(m *classify.LinearModel, p review.OwnershipProposal) (float64, error) {
	return adjudicatorProbability(m, OwnershipFeatures(p))
}
