// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/ai/oamrepo"
)

// scan uses deterministic candidate selection before calling the LLM. It
// deliberately does not attempt broad graph mining or mutate existing OAM.
func scan(ctx context.Context, graph oamrepo.Adapter, model ai.Model, modelName, journalPath string, limit int, classifier classify.Classifier, allowReview bool, out io.Writer) error {
	if journalPath == "" {
		return fmt.Errorf("-journal required for scan")
	}
	if limit < 1 || limit > 50 {
		return fmt.Errorf("-scan-limit must be 1..50")
	}
	assets, err := graph.FindAssets(ctx, "Organization", time.Time{}, 200)
	if err != nil {
		return err
	}
	pairs, err := ai.CandidatePairs(assets, limit)
	if err != nil {
		return err
	}
	store := &ai.Journal{Path: journalPath}
	inferrer := ai.Inferrer{Model: model, Plugin: "entity-resolution-scanner", ModelID: modelName, MinSources: 2}
	summary := struct {
		Candidates int `json:"candidates"`
		Analyzed   int `json:"analyzed"`
		Proposed   int `json:"proposed"`
		Skipped    int `json:"skipped"`
		Reviewed   int `json:"reviewed"`
		Escalated  int `json:"escalated"`
	}{Candidates: len(pairs)}
	for _, candidate := range pairs {
		if err := ctx.Err(); err != nil {
			return err
		}
		var permitted []string
		for _, label := range candidate.AllowedLabels {
			if oamrepo.AllowedRelation("Organization", label, "Organization") {
				permitted = append(permitted, label)
			}
		}
		candidate.AllowedLabels = permitted
		if len(permitted) == 0 {
			summary.Skipped++
			continue
		}
		first, err := graph.Evidence(ctx, candidate.SubjectID, 40)
		if err != nil {
			return err
		}
		second, err := graph.Evidence(ctx, candidate.ObjectID, 40)
		if err != nil {
			return err
		}
		candidate.Evidence = append(first, second...)
		independent := map[string]bool{}
		for _, ev := range candidate.Evidence {
			if ev.SourceID != "" {
				independent[ev.SourceID] = true
			}
		}
		if len(independent) < 2 {
			summary.Skipped++
			continue
		}
		summary.Analyzed++
		routing, err := inferrer.AnalyzeRouted(ctx, candidate, classifier, ai.RoutingPolicy{AllowLocalReview: allowReview})
		if err != nil {
			return fmt.Errorf("candidate %s -> %s: %w", candidate.SubjectID, candidate.ObjectID, err)
		}
		if routing.UsedGenerativeModel {
			summary.Escalated++
		}
		if routing.Decision == "review" {
			if err := store.SubmitTriage(candidate, routing); err != nil {
				return err
			}
			summary.Reviewed++
		}
		if routing.Proposal != nil {
			if err := store.Submit(*routing.Proposal); err != nil {
				return err
			}
			summary.Proposed++
		}
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}
