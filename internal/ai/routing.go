// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
)

// EvidenceSummary records the provenance that was available to the router.
// Distinct source IDs are an approximation, NOT proof of source independence.
type EvidenceSummary struct {
	EvidenceIDs      []string `json:"evidence_ids"`
	SourceIDs        []string `json:"source_ids"`
	SourceProperties int      `json:"source_properties"`
	Unattributed     int      `json:"unattributed"`
}

const OrganizationFeatureVersion = "oam-provenance-v1"
const OrganizationClassificationTask = "organization_relation"

// ExtractProvenanceFeatures produces bounded, non-semantic features exclusively
// from supplied, repository-verified OAM evidence. No model is asked to parse
// arbitrary web, DNS, or certificate text as an instruction.
// The caller MUST verify evidence IDs against the Asset Database first.
func ExtractProvenanceFeatures(c Candidate) (classify.Input, EvidenceSummary, error) {
	var out EvidenceSummary
	if c.SubjectID == "" || c.ObjectID == "" || c.SubjectID == c.ObjectID {
		return classify.Input{}, out, errors.New("invalid candidate endpoints")
	}
	if len(c.AllowedLabels) == 0 || len(c.Evidence) > 100 {
		return classify.Input{}, out, errors.New("invalid candidate taxonomy or evidence count")
	}
	evidenceIDs := make(map[string]string)
	sources := make(map[string]bool)
	for _, ev := range c.Evidence {
		if ev.ID == "" {
			return classify.Input{}, out, errors.New("evidence without ID")
		}
		if prior, ok := evidenceIDs[ev.ID]; ok {
			if prior != ev.SourceID {
				return classify.Input{}, out, fmt.Errorf("conflicting provenance for evidence %q", ev.ID)
			}
			continue
		}
		evidenceIDs[ev.ID] = ev.SourceID
		if ev.SourceID == "" {
			out.Unattributed++
		} else {
			sources[ev.SourceID] = true
		}
		if ev.Kind == "SourceProperty" && ev.SourceID != "" {
			out.SourceProperties++
		}
	}
	for id := range evidenceIDs {
		out.EvidenceIDs = append(out.EvidenceIDs, id)
	}
	for id := range sources {
		out.SourceIDs = append(out.SourceIDs, id)
	}
	sort.Strings(out.EvidenceIDs)
	sort.Strings(out.SourceIDs)
	n := len(evidenceIDs)
	denom := float64(n)
	var fraction float64
	if n > 0 {
		fraction = float64(out.SourceProperties) / denom
	}
	input := classify.Input{Task: OrganizationClassificationTask, Features: map[string]float64{
		"distinct_sources":         minFloat(float64(len(sources))/3, 1),
		"evidence_count":           minFloat(float64(n)/8, 1),
		"source_property_fraction": fraction,
		"unattributed_fraction":    frac(out.Unattributed, n),
	}}
	return input, out, nil
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
func frac(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) / float64(whole)
}

// RoutingPolicy is conservative: the default does not permit local negative
// skips. Even with calibrated predictions, explicit authorization is required.
type RoutingPolicy struct {
	AllowLocalReview    bool
	AllowCalibratedSkip bool
}

type RoutingResult struct {
	Decision            string               `json:"decision"` // needs_evidence, review, skip, escalate, proposed, no_proposal
	Reason              string               `json:"reason"`
	Prediction          *classify.Prediction `json:"prediction,omitempty"`
	Provenance          EvidenceSummary      `json:"provenance"`
	Proposal            *Proposal            `json:"proposal,omitempty"`
	UsedGenerativeModel bool                 `json:"used_generative_model"`
}

// AnalyzeRouted runs cheap classification first, escalating when needed.
// It never inserts OAM relationships. The caller decides how to persist a
// review-only routing result or an LLM proposal.
func (i Inferrer) AnalyzeRouted(ctx context.Context, c Candidate, classifier classify.Classifier, policy RoutingPolicy) (RoutingResult, error) {
	var out RoutingResult
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if i.MinSources < 2 {
		return out, errors.New("minimum independent sources must be >= 2")
	}
	input, summary, err := ExtractProvenanceFeatures(c)
	if err != nil {
		return out, err
	}
	out.Provenance = summary
	if len(summary.SourceIDs) < i.MinSources {
		out.Decision = "needs_evidence"
		out.Reason = "not enough distinct attributed sources; no generative request made"
		return out, nil
	}
	if classifier != nil {
		prediction, err := classifier.Classify(ctx, input)
		if err != nil {
			return out, fmt.Errorf("classify candidate: %w", err)
		}
		// Enforce feature schema agreement, even for custom classifier adapters.
		if prediction.FeatureVersion != OrganizationFeatureVersion {
			return out, fmt.Errorf("classifier feature version %q does not match %q", prediction.FeatureVersion, OrganizationFeatureVersion)
		}
		out.Prediction = &prediction
		if prediction.Decision == "review" && policy.AllowLocalReview {
			out.Decision = "review"
			out.Reason = "classifier triage: analyst review required; no relationship has been proposed or accepted"
			return out, nil
		}
		if prediction.Decision == "skip" && prediction.ScoreKind == "calibrated_probability" && policy.AllowCalibratedSkip {
			out.Decision = "skip"
			out.Reason = "calibrated classifier triage under explicit skip policy; not a statement of non-ownership"
			return out, nil
		}
		// Uncalibrated negatives ALWAYS escalate; classifier output is not evidence.
	}
	if i.Model == nil {
		out.Decision = "escalate"
		out.Reason = "generative model required to investigate this candidate"
		return out, nil
	}
	out.UsedGenerativeModel = true
	proposal, err := i.Analyze(ctx, c)
	if err != nil {
		return out, err
	}
	if proposal == nil {
		out.Decision = "no_proposal"
		out.Reason = "generative model found no supported relationship"
		return out, nil
	}
	out.Decision = "proposed"
	out.Reason = "proposal requires policy validation or human review"
	out.Proposal = proposal
	return out, nil
}
