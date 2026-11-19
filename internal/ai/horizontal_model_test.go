// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

func TestHorizontalFeatures(t *testing.T) {
	f := HorizontalFeatures([]string{lens.SigRegistrantOrg, lens.SigCertSubjectOrg}, 93)
	if f["signal:"+lens.SigRegistrantOrg] != 1 || f["signal:"+lens.SigCertSubjectOrg] != 1 {
		t.Errorf("per-signal features missing: %+v", f)
	}
	if f["signals"] <= 0 || f["confidence"] < 0.92 || f["confidence"] > 0.94 {
		t.Errorf("signals/confidence features wrong: %+v", f)
	}
	// Confidence is clamped to 0..1.
	if HorizontalFeatures(nil, 250)["confidence"] != 1 {
		t.Error("confidence should clamp to 1")
	}
}

func TestLoadHorizontalModelMissing(t *testing.T) {
	m, err := LoadHorizontalModel(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || m != nil {
		t.Errorf("a missing model file should be (nil, nil), got (%v, %v)", m, err)
	}
	s, err := LoadHorizontalScorer("")
	if err != nil || s != nil {
		t.Errorf("an empty journal path should yield no scorer, got (%v, %v)", s, err)
	}
}

func TestHorizontalModelProbability(t *testing.T) {
	m := HorizontalModel{LinearModel: &classify.LinearModel{
		ModelID: "test-horiz", Task: HorizontalTask, FeatureVersion: HorizontalFeatureVersion,
		SkipThreshold: 0.7, ReviewThreshold: 0.7,
		Classes: []classify.LinearClass{
			{Label: "unrelated", Bias: 0, Weights: map[string]float64{"signal:" + lens.SigCertSubjectOrg: 0}},
			{Label: "potential_relation", Bias: 0, Weights: map[string]float64{"signal:" + lens.SigCertSubjectOrg: 5}},
		},
	}}

	if m.ModelName() != "test-horiz" || m.Threshold() != 0.7 {
		t.Errorf("model name/threshold = %q/%v", m.ModelName(), m.Threshold())
	}

	// A candidate carrying the signal the model weighs scores above the
	// threshold; one without it stays at the 0.5 base, below threshold.
	hit, err := m.Probability([]string{lens.SigCertSubjectOrg}, 75)
	if err != nil || hit <= m.Threshold() {
		t.Errorf("probability with the weighted signal = %v (err %v), want > %v", hit, err, m.Threshold())
	}
	miss, err := m.Probability([]string{lens.SigSharedNameServer}, 65)
	if err != nil || miss >= m.Threshold() {
		t.Errorf("probability without the weighted signal = %v (err %v), want < %v", miss, err, m.Threshold())
	}
}
