// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The question evaluation set records user questions with what a correct
// answer must and must not contain. Every case runs offline in CI against a
// stored fixture graph (with recorded planner replies standing in for the
// model), and live with `amass ai eval` against a real model and Asset
// Database. A fix counts when the new case and every earlier one pass.
//
//go:embed questions/questions.json
var defaultEvalJSON []byte

// EvalCase is one question in the evaluation set.
type EvalCase struct {
	ID       string `json:"id"`
	Question string `json:"question"`
	Note     string `json:"note,omitempty"`
	// Narrate also asks for a verified cited summary.
	Narrate bool       `json:"narrate,omitempty"`
	Expect  EvalExpect `json:"expect"`
	// Offline runs the case against a named fixture in CI.
	Offline *EvalOffline `json:"offline,omitempty"`
	// Live holds the checks for a run against a real Asset Database.
	Live *EvalChecks `json:"live,omitempty"`
}

// EvalExpect holds checks that apply offline and live.
type EvalExpect struct {
	// Answer is the answer kind the question must compile to: paths,
	// route, hierarchy, controlled or third_party.
	Answer        string `json:"answer,omitempty"`
	SubjectType   string `json:"subject_type,omitempty"`
	Purpose       string `json:"purpose,omitempty"`
	MaxModelCalls *int   `json:"max_model_calls,omitempty"`
}

// EvalOffline names the fixture graph and the planner replies to replay.
type EvalOffline struct {
	Fixture        string     `json:"fixture"`
	PlannerReplies []string   `json:"planner_replies,omitempty"`
	Checks         EvalChecks `json:"checks"`
}

// EvalChecks are content checks on an answer. Results are the labels of the
// answer's assets: matched path destinations, vendors and controlled assets.
// All comparisons ignore case.
type EvalChecks struct {
	AnswerContains []string `json:"answer_contains,omitempty"`
	AnswerExcludes []string `json:"answer_excludes,omitempty"`
	ResultsInclude []string `json:"results_include,omitempty"`
	ResultsExclude []string `json:"results_exclude,omitempty"`
	MinResults     int      `json:"min_results,omitempty"`
	Complete       bool     `json:"complete,omitempty"`
	// NarrativeVerified requires a narrative that passed citation checks.
	NarrativeVerified bool `json:"narrative_verified,omitempty"`
}

// EvalResult is the outcome of one case.
type EvalResult struct {
	ID       string   `json:"id"`
	Question string   `json:"question"`
	Pass     bool     `json:"pass"`
	Failures []string `json:"failures,omitempty"`
	Answer   string   `json:"answer_kind"`
	// Plan describes the Query the question compiled to, so a live failure
	// shows what the model chose.
	Plan string `json:"plan,omitempty"`
	// Corrections are why the planner's rejected plans were rejected.
	Corrections []string      `json:"corrections,omitempty"`
	ModelCalls  int           `json:"model_calls"`
	Results     int           `json:"results"`
	Duration    time.Duration `json:"duration"`
	Text        string        `json:"answer"`
}

type evalSet struct {
	License string     `json:"_license"`
	About   string     `json:"_about"`
	Cases   []EvalCase `json:"cases"`
}

// LoadEvalCases parses an evaluation set and checks every case.
func LoadEvalCases(data []byte) ([]EvalCase, error) {
	var set evalSet
	if err := decodeStrict(data, &set); err != nil {
		return nil, fmt.Errorf("parse evaluation set: %w", err)
	}

	seen := map[string]bool{}
	for _, c := range set.Cases {
		if c.ID == "" || strings.TrimSpace(c.Question) == "" {
			return nil, errors.New("every evaluation case needs an id and a question")
		}
		if seen[c.ID] {
			return nil, fmt.Errorf("evaluation case %q is listed twice", c.ID)
		}
		if c.Expect.Answer != "" && c.Expect.Answer != TraversalRoute {
			if _, ok := answerKind(c.Expect.Answer); !ok {
				return nil, fmt.Errorf("evaluation case %q expects unknown answer %q", c.ID, c.Expect.Answer)
			}
		}

		seen[c.ID] = true
	}

	return set.Cases, nil
}

// DefaultEvalCases returns the embedded evaluation set.
func DefaultEvalCases() ([]EvalCase, error) {
	return LoadEvalCases(defaultEvalJSON)
}

// answerKindOf names the answer kind a Query runs.
func answerKindOf(q *Query) string {
	switch {
	case q == nil:
		return ""
	case q.Lens != "":
		return q.Lens
	case q.Traversal == TraversalHierarchy:
		return AnswerHierarchy
	case q.Traversal == TraversalRoute:
		return TraversalRoute
	}

	return AnswerPaths
}

// resultLabels lists the labels of an investigation's answer assets.
func resultLabels(inv Investigation) []string {
	var out []string
	for _, m := range inv.Matches {
		if len(m.Nodes) > 0 {
			out = append(out, assetLabel(m.Nodes[len(m.Nodes)-1]))
		}
	}
	if r := inv.ThirdPartyReport; r != nil {
		for _, v := range r.Vendors {
			out = append(out, v.Vendor)
		}
	}
	if r := inv.TableReport; r != nil {
		for _, row := range r.Rows {
			out = append(out, strings.Join(row, " | "))
		}
	}
	if r := inv.GapReport; r != nil {
		for _, c := range r.Candidates {
			out = append(out, c.Decision+" "+c.Type+" "+c.Asset)
		}
	}
	if r := inv.FamilyReport; r != nil {
		for _, m := range r.Members {
			out = append(out, m.Relation+" "+assetLabel(m.Organization))
		}
		for _, d := range r.RelatedDomains {
			out = append(out, "related "+d.Domain)
		}
	}

	return out
}

// RunEvalCase asks c.Question and scores the investigation against c.Expect
// and checks.
func (a Agent) RunEvalCase(ctx context.Context, c EvalCase, checks EvalChecks, opts AdaptiveOptions) EvalResult {
	res := EvalResult{ID: c.ID, Question: c.Question}
	started := time.Now()
	inv, err := a.AskAdaptive(ctx, c.Question, opts)
	if err == nil && c.Narrate {
		err = a.AttachNarrative(ctx, c.Question, &inv)
	}

	res.Duration = time.Since(started)
	res.Answer, res.Text = answerKindOf(inv.Query), inv.Answer
	if inv.Query != nil {
		res.Plan = inv.Query.Describe()
		res.Corrections = inv.Query.PlanCorrections
	}
	if inv.Usage != nil {
		res.ModelCalls = inv.Usage.Calls
	}

	labels := resultLabels(inv)
	res.Results = len(labels)
	fail := func(format string, args ...any) { res.Failures = append(res.Failures, fmt.Sprintf(format, args...)) }
	if err != nil {
		fail("error: %v", err)
	}
	if c.Expect.Answer != "" && res.Answer != c.Expect.Answer {
		fail("answer kind %q, want %q", res.Answer, c.Expect.Answer)
	}
	if c.Expect.SubjectType != "" && (inv.Query == nil || inv.Query.Subject.Type != c.Expect.SubjectType) {
		fail("subject type is not %s", c.Expect.SubjectType)
	}
	if c.Expect.Purpose != "" && (inv.Query == nil || inv.Query.Purpose != c.Expect.Purpose) {
		fail("purpose is not %s", c.Expect.Purpose)
	}
	if c.Expect.MaxModelCalls != nil && res.ModelCalls > *c.Expect.MaxModelCalls {
		fail("%d model calls, want at most %d", res.ModelCalls, *c.Expect.MaxModelCalls)
	}

	text := strings.ToLower(inv.Answer)
	for _, s := range checks.AnswerContains {
		if !strings.Contains(text, strings.ToLower(s)) {
			fail("answer does not contain %q", s)
		}
	}
	for _, s := range checks.AnswerExcludes {
		if strings.Contains(text, strings.ToLower(s)) {
			fail("answer contains %q", s)
		}
	}

	has := func(want string) bool {
		for _, l := range labels {
			if strings.Contains(strings.ToLower(l), strings.ToLower(want)) {
				return true
			}
		}

		return false
	}
	for _, s := range checks.ResultsInclude {
		if !has(s) {
			fail("results do not include %q", s)
		}
	}
	for _, s := range checks.ResultsExclude {
		if has(s) {
			fail("results include %q", s)
		}
	}
	if res.Results < checks.MinResults {
		fail("%d results, want at least %d", res.Results, checks.MinResults)
	}
	if checks.Complete && inv.Incomplete {
		fail("answer is incomplete")
	}
	if checks.NarrativeVerified {
		switch {
		case inv.Narrative == nil:
			fail("no narrative was written")
		case !inv.Narrative.Verified:
			fail("narrative rejected: %s", strings.Join(inv.Narrative.Rejected, "; "))
		}
	}

	res.Pass = len(res.Failures) == 0
	return res
}

// RunEvalLive runs every case with live checks.
func (a Agent) RunEvalLive(ctx context.Context, cases []EvalCase, perCase time.Duration, opts AdaptiveOptions) []EvalResult {
	out := make([]EvalResult, 0, len(cases))
	for _, c := range cases {
		checks := EvalChecks{}
		if c.Live != nil {
			checks = *c.Live
		}

		cctx, cancel := context.WithTimeout(ctx, perCase)
		out = append(out, a.RunEvalCase(cctx, c, checks, opts))
		cancel()
	}

	return out
}

// FormatEvalResults renders results as a plain-text table with a summary.
func FormatEvalResults(results []EvalResult) string {
	var b strings.Builder
	passed := 0
	for _, r := range results {
		status := "FAIL"
		if r.Pass {
			status = "pass"
			passed++
		}

		fmt.Fprintf(&b, "%-4s %-28s %-12s calls=%d results=%d %6.1fs\n", status, r.ID, r.Answer, r.ModelCalls,
			r.Results, r.Duration.Seconds())
		for _, f := range r.Failures {
			fmt.Fprintf(&b, "       - %s\n", f)
		}
		if !r.Pass && r.Plan != "" {
			fmt.Fprintf(&b, "       plan: %s\n", r.Plan)
		}
		if !r.Pass {
			for i, c := range r.Corrections {
				fmt.Fprintf(&b, "       rejected plan %d: %s\n", i+1, c)
			}
		}
	}

	fmt.Fprintf(&b, "%d of %d passed\n", passed, len(results))
	return b.String()
}

// MarshalEvalResults renders results as indented JSON.
func MarshalEvalResults(results []EvalResult) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}
