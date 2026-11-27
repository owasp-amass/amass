// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"math"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// The horizontal model learns how much each horizontal signal counts toward a
// related domain belonging to an organization, from people's decisions on
// scope expansions, in place of the hand-set catalog weights the
// HorizontalScore uses by default. Until one is trained the weighted score
// decides, so the model is an optional adjudicator, never a requirement.
const (
	HorizontalTask           = "horizontal_expansion"
	HorizontalFeatureVersion = "horizontal-signals-v1"
)

// HorizontalKind is the horizontal expansion question: does a related domain
// tied to an organization by supporting evidence only belong in its scope.
var HorizontalKind = &AdjudicatorKind{
	Name:           "horizontal",
	Question:       "whether a related domain belongs in an organization's scope",
	Task:           HorizontalTask,
	FeatureVersion: HorizontalFeatureVersion,
	File:           "horizontal-model.json",
	Examples:       horizontalExamples,
	ModelExamples:  horizontalModelExamples,
	MinExamples:    20,
	MinPrecision:   0.9,
	MinThreshold:   0.7,
	UsedBy:         "the engine's horizontal correlation, for domains tied by supporting evidence only",
}

// HorizontalFeatures describes a related-domain candidate for the horizontal
// model: one feature per matched signal ("signal:<id>"), the signal count and
// the weighted confidence, each in 0..1. New signals become features without
// code changes.
func HorizontalFeatures(signalIDs []string, confidence int) map[string]float64 {
	f := map[string]float64{}
	for _, id := range signalIDs {
		f["signal:"+id] = 1
	}
	f["signals"] = math.Min(float64(len(signalIDs)), 3) / 3
	f["confidence"] = math.Min(math.Max(float64(confidence), 0), 100) / 100
	return f
}

// horizontalExamples are people's decisions on domain scope expansions: an
// approval is positive; a rejection, or a retraction of an applied
// expansion, negative. No amass-ai decision is a label.
func horizontalExamples(j *review.Journal) ([]classify.LabeledExample, []string, error) {
	all, err := j.ScopeExpansions()
	if err != nil {
		return nil, nil, err
	}

	var rows []classify.LabeledExample
	for _, e := range all {
		if e.Kind() != review.DefaultScopeAssetType || e.Reviewer == "" ||
			strings.HasPrefix(e.Reviewer, review.InferenceSource) {
			continue
		}

		var label string
		switch e.Status {
		case review.ProposalApplied:
			label = labelPositive
		case review.ProposalRejected, review.ProposalRetracted:
			label = labelNegative
		default:
			continue
		}
		rows = append(rows, classify.LabeledExample{GroupID: e.ID, Label: label,
			Features: HorizontalFeatures(e.SignalIDs, e.Confidence)})
	}
	return rows, featureNames(rows), nil
}

// horizontalModelExamples are the main model's confident answers on
// domains no person decided: expansions it applied at modelLabelConfidence
// or above that stand (a person's retraction or the re-check replaces
// them) are positive, and its rejections at that confidence, kept as advice
// on the pending expansion, are negative. A person's decision replaces the
// model's.
func horizontalModelExamples(j *review.Journal) ([]classify.LabeledExample, error) {
	all, err := j.ScopeExpansions()
	if err != nil {
		return nil, err
	}

	var rows []classify.LabeledExample
	for _, e := range all {
		if e.Kind() != review.DefaultScopeAssetType {
			continue
		}
		var label string
		switch a := e.Advice; {
		case e.Status == review.ProposalApplied && decidedByMainModel(e.Reviewer) &&
			e.DecidedConfidence >= modelLabelConfidence:
			label = labelPositive
		case e.Status == review.ProposalPending && a != nil && isMainModel(a.Model) &&
			a.Decision == review.ScopeAdviceReject && a.Confidence >= modelLabelConfidence:
			label = labelNegative
		default:
			continue
		}
		rows = append(rows, classify.LabeledExample{GroupID: e.ID, Label: label,
			Features: HorizontalFeatures(e.SignalIDs, e.Confidence)})
	}
	return rows, nil
}

// LoadHorizontalScorer loads the newest trained horizontal model for the
// journal (HorizontalKind.LoadFor), or returns a nil scorer (and no error) when
// there is none, so a caller can set it unconditionally and let the weighted
// score decide when no model has been trained.
func LoadHorizontalScorer(j *review.Journal) (*HorizontalModel, error) {
	m, err := HorizontalKind.LoadFor(j)
	if err != nil || m == nil {
		return nil, err
	}
	return &HorizontalModel{LinearModel: m}, nil
}

// HorizontalModel adjudicates a corroboration-only related-domain candidate with
// a trained model.
type HorizontalModel struct{ *classify.LinearModel }

// ModelName returns the model's identifier.
func (m HorizontalModel) ModelName() string { return m.ModelID }

// Threshold is the probability at or above which the model promotes a
// corroboration-only candidate to a scope expansion.
func (m HorizontalModel) Threshold() float64 { return m.ReviewThreshold }

// Probability scores a candidate's signals with the model, ignoring features the
// model never saw.
func (m HorizontalModel) Probability(signalIDs []string, confidence int) (float64, error) {
	return adjudicatorProbability(m.LinearModel, HorizontalFeatures(signalIDs, confidence))
}
