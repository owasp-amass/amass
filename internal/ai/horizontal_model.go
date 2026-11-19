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

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
)

// The horizontal model learns how much each horizontal signal counts toward a
// related domain belonging to an organization, from review decisions, in place
// of the hand-set catalog weights the HorizontalScore uses by default. It
// mirrors the ownership model; until one is trained the weighted score decides,
// so the model is an optional adjudicator, never a requirement.
const (
	HorizontalTask           = "horizontal_expansion"
	HorizontalFeatureVersion = "horizontal-signals-v1"
	// HorizontalModelFile is the model's file name beside the journal.
	HorizontalModelFile = "horizontal-model.json"
)

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

// HorizontalModelPath is where the horizontal model for a journal lives.
func HorizontalModelPath(journal string) string {
	return filepath.Join(filepath.Dir(journal), HorizontalModelFile)
}

// LoadHorizontalModel reads the horizontal model at path. A missing file is no
// model, so the weighted score decides.
func LoadHorizontalModel(path string) (*classify.LinearModel, error) {
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
	if m.Task != HorizontalTask || m.FeatureVersion != HorizontalFeatureVersion {
		return nil, fmt.Errorf("%s is a %s/%s model, not %s/%s", path, m.Task, m.FeatureVersion, HorizontalTask,
			HorizontalFeatureVersion)
	}

	return m, nil
}

// LoadHorizontalScorer loads the trained horizontal model beside journalPath, or
// returns a nil scorer (and no error) when there is none, so a caller can set it
// unconditionally and let the weighted score decide when no model has been
// trained.
func LoadHorizontalScorer(journalPath string) (*HorizontalModel, error) {
	if journalPath == "" {
		return nil, nil
	}

	m, err := LoadHorizontalModel(HorizontalModelPath(journalPath))
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
	known := map[string]bool{}
	for _, name := range m.Features() {
		known[name] = true
	}

	f := map[string]float64{}
	for k, v := range HorizontalFeatures(signalIDs, confidence) {
		if known[k] {
			f[k] = v
		}
	}

	return m.ClassifyUnrestricted(f)
}
