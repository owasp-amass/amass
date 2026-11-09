// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"context"
	"errors"
	"fmt"
)

// LabeledCase is a held-out, analyst-reviewed evaluation item. Ground truth
// labels are task-specific and must not be sourced from the classifier itself.
type LabeledCase struct {
	ID            string `json:"id"`
	Input         Input  `json:"input"`
	ExpectedLabel string `json:"expected_label"`
}

// Metrics separate prediction quality from inference routing. "escalate"
// means abstention, not an incorrect classification.
type Metrics struct {
	Total        int `json:"total"`
	Correct      int `json:"correct"`
	Incorrect    int `json:"incorrect"`
	Skipped      int `json:"skipped"`
	Reviewed     int `json:"reviewed"`
	Escalated    int `json:"escalated"`
	UnsafeSkips  int `json:"unsafe_skips"`  // ground-truth relation was incorrectly skipped
	FalseReviews int `json:"false_reviews"` // unrelated pair sent for human review
}

func Evaluate(ctx context.Context, model Classifier, cases []LabeledCase) (Metrics, error) {
	var out Metrics
	if model == nil || len(cases) == 0 || len(cases) > 100000 {
		return out, errors.New("valid classifier and 1..100000 held-out cases required")
	}

	seen := map[string]bool{}
	for _, c := range cases {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if c.ID == "" || seen[c.ID] {
			return out, fmt.Errorf("duplicate/invalid case ID %q", c.ID)
		}

		seen[c.ID] = true
		if c.ExpectedLabel != "unrelated" && c.ExpectedLabel != "potential_relation" {
			return out, fmt.Errorf("unknown expected label in case %q", c.ID)
		}

		got, err := model.Classify(ctx, c.Input)
		if err != nil {
			return out, fmt.Errorf("evaluate case %q: %w", c.ID, err)
		}
		if got.Label != "unrelated" && got.Label != "potential_relation" {
			return out, fmt.Errorf("classifier produced unsupported label in case %q", c.ID)
		}
		switch got.Decision {
		case "skip":
			out.Skipped++
			if c.ExpectedLabel != "unrelated" {
				out.UnsafeSkips++
			}
		case "review":
			out.Reviewed++
			if c.ExpectedLabel != "potential_relation" {
				out.FalseReviews++
			}
		case "escalate":
			out.Escalated++
		default:
			return out, fmt.Errorf("unsupported decision in case %q", c.ID)
		}
		if got.Label == c.ExpectedLabel {
			out.Correct++
		} else {
			out.Incorrect++
		}

		out.Total++
	}

	return out, nil
}
