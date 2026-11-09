// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package classify provides a provider-independent local classification baseline.
// No classification result constitutes evidence of ownership or modifies OAM.
package classify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
)

type Input struct {
	Task     string             `json:"task"`
	Features map[string]float64 `json:"features"`
}
type Prediction struct {
	Label          string  `json:"label"`
	Score          float64 `json:"score"`
	ScoreKind      string  `json:"score_kind"`
	ModelID        string  `json:"model_id"`
	FeatureVersion string  `json:"feature_version"`
	Decision       string  `json:"decision"`
}
type Classifier interface {
	Classify(context.Context, Input) (Prediction, error)
}
type LinearClass struct {
	Label   string             `json:"label"`
	Bias    float64            `json:"bias"`
	Weights map[string]float64 `json:"weights"`
}
type LinearModel struct {
	ModelID         string        `json:"model_id"`
	Task            string        `json:"task"`
	FeatureVersion  string        `json:"feature_version"`
	Classes         []LinearClass `json:"classes"`
	SkipThreshold   float64       `json:"skip_threshold"`
	ReviewThreshold float64       `json:"review_threshold"`
}

func Load(r io.Reader) (*LinearModel, error) {
	dec := json.NewDecoder(io.LimitReader(r, 128<<10))
	dec.DisallowUnknownFields()
	var m LinearModel
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("unexpected trailing model data")
	}
	return &m, m.Validate()
}
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func (m *LinearModel) Validate() error {
	if m == nil || m.ModelID == "" || m.Task == "" || m.FeatureVersion == "" || len(m.Classes) != 2 {
		return errors.New("two-class model requires ID, task and feature version")
	}
	if m.SkipThreshold < .5 || m.SkipThreshold > 1 || m.ReviewThreshold < .5 || m.ReviewThreshold > 1 || !finite(m.SkipThreshold) || !finite(m.ReviewThreshold) {
		return errors.New("thresholds outside 0.5..1")
	}
	names := map[string]bool{}
	features := map[string]bool{}
	for _, c := range m.Classes {
		if (c.Label != "unrelated" && c.Label != "potential_relation") || names[c.Label] || !finite(c.Bias) || math.Abs(c.Bias) > 100 {
			return errors.New("invalid class label or bias")
		}
		names[c.Label] = true
		for k, w := range c.Weights {
			if k == "" || len(k) > 80 || !finite(w) || math.Abs(w) > 100 {
				return fmt.Errorf("invalid weight for %q", k)
			}
			features[k] = true
		}
	}
	if len(names) != 2 || len(features) == 0 || len(features) > 64 {
		return errors.New("invalid class set or feature count")
	}
	return nil
}
func (m *LinearModel) Classify(ctx context.Context, in Input) (Prediction, error) {
	var out Prediction
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if err := m.Validate(); err != nil {
		return out, err
	}
	if in.Task != m.Task || len(in.Features) == 0 || len(in.Features) > 64 {
		return out, errors.New("task or feature dimension mismatch")
	}
	allowed := map[string]bool{}
	for _, c := range m.Classes {
		for k := range c.Weights {
			allowed[k] = true
		}
	}
	for k, v := range in.Features {
		if !allowed[k] || !finite(v) || v < 0 || v > 1 {
			return out, fmt.Errorf("invalid feature %q", k)
		}
	}
	logits := make([]float64, 2)
	for i, c := range m.Classes {
		logits[i] = c.Bias
		for k, v := range in.Features {
			logits[i] += c.Weights[k] * v
		}
	}
	peak := math.Max(logits[0], logits[1])
	probs := []float64{math.Exp(logits[0] - peak), math.Exp(logits[1] - peak)}
	d := probs[0] + probs[1]
	for i := range probs {
		probs[i] /= d
	}
	best := 0
	if probs[1] > probs[0] {
		best = 1
	}
	label, score := m.Classes[best].Label, probs[best]
	action := "escalate"
	// A skip is a triage decision, NEVER a claim that two OAM assets are unrelated.
	if label == "unrelated" && score >= m.SkipThreshold {
		action = "skip"
	}
	if label == "potential_relation" && score >= m.ReviewThreshold {
		action = "review"
	}
	return Prediction{Label: label, Score: score, ScoreKind: "uncalibrated_softmax", ModelID: m.ModelID, FeatureVersion: m.FeatureVersion, Decision: action}, nil
}
func (m *LinearModel) Features() []string {
	if m == nil {
		return nil
	}
	set := map[string]bool{}
	for _, c := range m.Classes {
		for k := range c.Weights {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
