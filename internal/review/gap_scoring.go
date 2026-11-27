// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// ScoreGapCandidates re-scores an ownership-gap report with a trained model,
// so an interactive answer ranks and decides the same way automatic
// attribution does. For each attachable candidate the model can score (one
// attachment, not weak or ambiguous — the same set OwnershipProposals builds),
// the candidate's score becomes the model's probability of ownership and its
// decision is propose when that probability reaches the model's threshold,
// otherwise review. Weak and ambiguous candidates keep the rules' decision.
// A nil scorer leaves the report unchanged, so the rules decide.
func ScoreGapCandidates(report *lens.OwnershipGapReport, scorer OwnershipScorer) error {
	if report == nil || scorer == nil {
		return nil
	}

	byID := map[string]OwnershipProposal{}
	for _, p := range OwnershipProposals(*report) {
		byID[p.ID] = p
	}

	for i := range report.Candidates {
		c := &report.Candidates[i]
		if c.Attachment == nil {
			continue
		}

		p, ok := byID[ProposalID(*c.Attachment)]
		if !ok {
			// Weak or ambiguous: the model never writes it, so leave the rules'
			// decision in place.
			continue
		}

		prob, err := scorer.Probability(p)
		if err != nil {
			return err
		}

		c.Score = prob
		if prob >= scorer.Threshold() {
			c.Decision = lens.GapPropose
		} else {
			c.Decision = lens.GapReview
		}
	}

	return nil
}
