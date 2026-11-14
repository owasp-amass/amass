// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/ai/review"
)

// AdviseOwnership asks the model to recommend approving or rejecting p and
// verifies the rationale's citations, retrying once with the problems
// found. Unverified advice is returned with Verified false.
func (a Agent) AdviseOwnership(ctx context.Context, p review.OwnershipProposal, model string) (review.OwnershipAdvice, error) {
	adv := review.OwnershipAdvice{ProposalID: p.ID, Recommendation: review.AdviseUnsure, Model: model}
	if a.Model == nil {
		return adv, errors.New("a model is required to advise on a proposal")
	}

	bundle := review.ProposalBundle(p)
	if len(bundle.Items) == 0 {
		adv.Problems = []string{"the proposal has no stored relationships to cite"}
		return adv, nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "PROPOSAL: record %s as the owner of %s %s by storing %s.\n", p.Owner, p.AssetType, p.Asset, p.Edge)
	fmt.Fprintf(&b, "SIGNALS: %s\n", strings.Join(p.Signals, "; "))
	if len(p.Gains) > 0 {
		fmt.Fprintf(&b, "IT WOULD ALSO BRING UNDER THE ORGANIZATION: %s\n", strings.Join(p.Gains, ", "))
	}

	b.WriteString("\nEVIDENCE:\n" + bundle.String())
	history := []llm.Message{{Role: "system", Text: review.AdviceInstructions}, {Role: "user", Text: b.String()}}
	for attempt := 0; attempt < narrativeMaxAttempt; attempt++ {
		resp, err := a.Model.Generate(ctx, history, nil)
		if err != nil {
			return adv, err
		}

		text := strings.TrimSpace(stripReasoning(resp.Text))
		first, rest, _ := strings.Cut(text, "\n")
		var problems []string
		m := review.RecommendationLine.FindStringSubmatch(first)
		if m == nil {
			problems = append(problems, "the first line is not RECOMMENDATION: approve, reject or unsure")
		}

		rationale := strings.TrimSpace(rest)
		problems = append(problems, VerifyCitations(rationale, bundle)...)
		if len(problems) == 0 {
			adv.Recommendation, adv.Rationale, adv.Verified, adv.Problems = strings.ToLower(m[1]), rationale, true, nil
			return adv, nil
		}

		adv.Problems = problems
		history = append(history, llm.Message{Role: "assistant", Text: resp.Text}, llm.Message{Role: "user",
			Text: "The review was rejected: " + strings.Join(problems, "; ") + ". Reply again: the RECOMMENDATION " +
				"line, then rationale sentences that each cite evidence items mentioning every asset they name."})
	}

	return adv, nil
}
