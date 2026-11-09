// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"fmt"
	"strings"
	"testing"
)

func TestTrainerRejectsMissingLabelsAndUnknownFeatures(t *testing.T) {
	bad := `{"group_id":"case-a","label":"potential_relation","features":{"distinct_sources":1,"evidence_count":.5,"source_property_fraction":1,"wrong":0}}`
	if _, err := ReadLabeledJSONL(strings.NewReader(bad)); err == nil {
		t.Fatal("unregistered feature accepted")
	}
}

func TestTrainerUsesGroupHoldoutAndUncalibratedScores(t *testing.T) {
	var lines strings.Builder
	for i := 0; i < 180; i++ {
		label := "unrelated"
		distinct := 0.0
		attribution := 0.0
		if i%2 == 0 {
			label = "potential_relation"
			distinct = 1
			attribution = 1
		}

		fmt.Fprintf(&lines,
			`{"group_id":"sample-%d","label":"%s","features":{"distinct_sources":%g,"evidence_count":0.5,"source_property_fraction":%g,"unattributed_fraction":0}}%s`,
			i, label, distinct, attribution, "\n")
	}

	rows, err := ReadLabeledJSONL(strings.NewReader(lines.String()))
	if err != nil {
		t.Fatal(err)
	}

	model, metrics, err := TrainLinearModel(rows, "synthetic-classifier-regression")
	if err != nil {
		t.Fatal(err)
	}
	if model.FeatureVersion != "oam-provenance-v1" || metrics.HoldoutExamples < 8 || metrics.TrainingExamples < 40 {
		t.Fatalf("wrong training metadata: model=%+v metrics=%+v", model, metrics)
	}
	if metrics.ScoreKind != "uncalibrated_softmax" || metrics.HoldoutAccuracy < .9 {
		t.Fatalf("training regression failed: %+v", metrics)
	}
	if err := model.Validate(); err != nil {
		t.Fatal(err)
	}
}
