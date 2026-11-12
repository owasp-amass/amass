// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
)

// The ownership model learns how much each kind of signal counts from
// review decisions in the journal, in place of the hand-set weights of
// scoreGap.
const (
	OwnershipTask           = "ownership_attribution"
	OwnershipFeatureVersion = "ownership-signals-v1"
	// AttributionModelFile is the model's file name beside the journal.
	AttributionModelFile = "attribution-model.json"
)

// OwnershipFeatures describes a proposal for the ownership model. Every
// value is in 0..1. Besides the totals per signal kind, each signal adds
// "kind:route", where route is the last word of how the signal was found
// (the shared value's type for identity, the controlled asset's type for
// hosting, the listing relationship for co-listing), and "signal:id" for
// its catalog entry. New signals and routes become features without code
// changes.
func OwnershipFeatures(p OwnershipProposal) map[string]float64 {
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
	f["gains"] = math.Min(float64(len(p.Gains)), gapMaxGains) / gapMaxGains
	return f
}

// OwnershipLabel is a proposal's training label from its review outcome:
// a person's approval is positive; a rejection or retraction is negative.
// Pending proposals and automatic writes are not labels, so the model never
// learns from its own decisions.
func OwnershipLabel(e OwnershipEntry) (string, bool) {
	if e.Outcome == nil {
		return "", false
	}

	switch e.Status {
	case ProposalApplied:
		if e.Outcome.Reviewer == AutomaticReviewer {
			return "", false
		}

		return "potential_relation", true
	case ProposalRejected, ProposalRetracted:
		// A re-check retracts when evidence disappears; no person decided.
		if e.Outcome.Reviewer == RecheckReviewer {
			return "", false
		}

		return "unrelated", true
	}

	return "", false
}

// OwnershipTrainingSet turns reviewed journal entries into labeled examples
// and the feature list they use.
func OwnershipTrainingSet(entries []OwnershipEntry) ([]classify.LabeledExample, classify.LinearSpec) {
	var rows []classify.LabeledExample
	names := map[string]bool{}
	for _, e := range entries {
		// Departments are decided on other evidence than ownership signals.
		if e.Proposal.Kind != "" {
			continue
		}

		label, ok := OwnershipLabel(e)
		if !ok {
			continue
		}

		f := OwnershipFeatures(e.Proposal)
		for k := range f {
			names[k] = true
		}

		rows = append(rows, classify.LabeledExample{GroupID: e.Proposal.ID, Label: label, Features: f})
	}

	features := make([]string, 0, len(names))
	for k := range names {
		features = append(features, k)
	}

	sort.Strings(features)
	return rows, classify.LinearSpec{Task: OwnershipTask, FeatureVersion: OwnershipFeatureVersion, Features: features}
}

// AttributionModelPath is where the ownership model for a journal lives.
func AttributionModelPath(journal string) string {
	return filepath.Join(filepath.Dir(journal), AttributionModelFile)
}

// LoadAttributionModel reads the ownership model at path. A missing file is
// no model, so the rules decide.
func LoadAttributionModel(path string) (*classify.LinearModel, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()
	m, err := classify.Load(f)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	if m.Task != OwnershipTask || m.FeatureVersion != OwnershipFeatureVersion {
		return nil, fmt.Errorf("%s is a %s/%s model, not %s/%s", path, m.Task, m.FeatureVersion, OwnershipTask,
			OwnershipFeatureVersion)
	}

	return m, nil
}

// ownershipProbability scores p with m, ignoring features m never saw.
func ownershipProbability(m *classify.LinearModel, p OwnershipProposal) (float64, error) {
	known := map[string]bool{}
	for _, name := range m.Features() {
		known[name] = true
	}

	f := map[string]float64{}
	for k, v := range OwnershipFeatures(p) {
		if known[k] {
			f[k] = v
		}
	}

	return m.ClassifyUnrestricted(f)
}

// Ownership model bounds.
const (
	// minOwnershipThreshold is the lowest probability that may ever write.
	minOwnershipThreshold = 0.7
	// minOwnershipPrecision is the held-out precision a model needs before
	// it may decide automatic writes.
	minOwnershipPrecision = 0.9
)

// TrainOwnershipModel trains the ownership model on reviewed proposals. The
// threshold for an automatic write is set just above the highest
// probability any rejected or retracted proposal received, and never below
// minOwnershipThreshold, so the model writes nothing a reviewer turned down.
// A model whose held-out precision is below minOwnershipPrecision is
// refused.
func TrainOwnershipModel(rows []classify.LabeledExample, spec classify.LinearSpec,
	modelID string) (*classify.LinearModel, classify.TrainingMetrics, error) {
	m, metrics, err := classify.TrainLinear(rows, modelID, spec)
	if err != nil {
		return nil, metrics, err
	}
	if metrics.HoldoutPotentialPrecision < minOwnershipPrecision {
		return nil, metrics, fmt.Errorf("held-out precision %.2f is below %.2f; review more proposals and train again",
			metrics.HoldoutPotentialPrecision, minOwnershipPrecision)
	}

	threshold := minOwnershipThreshold
	for _, r := range rows {
		if r.Label != "unrelated" {
			continue
		}

		prob, err := m.ClassifyUnrestricted(r.Features)
		if err != nil {
			return nil, metrics, err
		}

		threshold = math.Max(threshold, prob+0.01)
	}
	if threshold > 0.99 {
		return nil, metrics, errors.New("rejected proposals score too close to approved ones to write any automatically")
	}

	m.ReviewThreshold = threshold
	return m, metrics, m.Validate()
}
