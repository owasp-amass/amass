// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"context"
	"errors"
	"fmt"
	"math"
)

// EvidenceTriage is the provider-independent default classifier when no
// supervised, versioned classifier artifact is available. It interprets
// bounded, extracted OAM provenance features as a workflow-routing signal.
//
// More source tags do not establish independent evidence,
// legal ownership or a probability. This code never decides "unrelated",
// skips a possible relation, creates a proposal or writes OAM edges.
func EvidenceTriage(in Input) (Prediction, error) {
	const task = "organization_relation"
	const version = "oam-provenance-v1"
	output := Prediction{
		Label:          "unknown",
		Score:          0,
		ScoreKind:      "rules_no_probability",
		ModelID:        "oam-evidence-triage-v1",
		FeatureVersion: version,
		Decision:       "escalate",
	}
	if in.Task != task {
		return Prediction{}, fmt.Errorf("unsupported evidence triage task %q", in.Task)
	}
	if len(in.Features) != 4 {
		return Prediction{}, errors.New("expected exactly four OAM provenance features")
	}

	fields := []string{"distinct_sources", "evidence_count", "source_property_fraction", "unattributed_fraction"}
	for _, field := range fields {
		value, ok := in.Features[field]
		if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
			return Prediction{}, fmt.Errorf("invalid OAM provenance feature %q", field)
		}
	}
	// Only route candidates with meaningful attributed observations to a
	// human review queue. All other cases require more evidence or an LLM.
	// This is not a positive classification of the actual relationship.
	if in.Features["distinct_sources"] >= 2.0/3.0 &&
		in.Features["evidence_count"] >= 0.25 &&
		in.Features["source_property_fraction"] >= 0.5 &&
		in.Features["unattributed_fraction"] <= 0.25 {
		output.Decision = "review"
	}

	return output, nil
}

// EvidenceRuleClassifier is the zero-config default classifier. It scores
// no probabilities, uses only the verified OAM feature vector supplied
// by the caller and can be replaced by a trained linear model or HTTP
// classification service without changing inference providers.
type EvidenceRuleClassifier struct{}

var _ Classifier = EvidenceRuleClassifier{}

func (EvidenceRuleClassifier) Classify(ctx context.Context, in Input) (Prediction, error) {
	if err := ctx.Err(); err != nil {
		return Prediction{}, err
	}

	return EvidenceTriage(in)
}
