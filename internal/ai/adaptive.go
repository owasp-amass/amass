// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// InvestigationGoal describes a requested result, not a predicted fixed-hop path.
type InvestigationGoal struct {
	Subject       PlanSubject    `json:"subject"`
	TargetTypes   []string       `json:"target_types"`
	Direction     string         `json:"direction"`
	Purpose       string         `json:"purpose"` // connected or ultimate_parent
	Relationships []GoalRelation `json:"relationships,omitempty"`
	PathRule      string         `json:"path_rule,omitempty"`
	// Answer is the kind of answer the planner chose (see answerKinds);
	// empty means paths.
	Answer string `json:"answer,omitempty"`
	// Columns are the table columns for the table answer kind.
	Columns []lens.TableColumn `json:"columns,omitempty"`
}

type AdaptiveOptions struct {
	MaxDepth         int
	MaxMatches       int
	MaxPathsPerAsset int
	MaxExpansions    int
	GuidanceRounds   int // 0 disables optional intermediate guidance; positive values 1..3
	MaxInventory     int // names listed by a hierarchy inventory; 0 uses MaxMatches, then the default
}

type adaptiveSelection struct {
	SelectedPathIDs  []string `json:"selected_path_ids,omitempty"`
	SelectedAssetIDs []string `json:"selected_asset_ids,omitempty"` // backward-compatible
}

type adaptiveCandidate struct {
	PathID        string              `json:"path_id"`
	AssetID       string              `json:"asset_id"`
	AssetType     string              `json:"asset_type"`
	Display       string              `json:"display"`
	Depth         int                 `json:"depth"`
	Path          string              `json:"path"`
	SourceStatus  string              `json:"source_status,omitempty"`
	WeakestEdgeID string              `json:"weakest_edge_id,omitempty"`
	Coverage      PathSourceCoverage  `json:"source_tag_coverage"`
	EdgeSources   []EdgeSourceSummary `json:"edge_sources,omitempty"`
}

func parseGoal(raw string, selectors []graph.AssetSearchSchema) (InvestigationGoal, error) {
	var goal InvestigationGoal
	value := strings.TrimSpace(raw)
	value = llm.ModelJSON(value)
	data, err := canonicalizeSelectorFields([]byte(strings.TrimSpace(value)), selectors)
	if err != nil {
		return goal, err
	}
	if err := graph.DecodeStrict(data, &goal); err != nil {
		return goal, fmt.Errorf("invalid investigation goal: %w", err)
	}

	goal.Subject = normalizePlannedSubject(goal.Subject, selectors)
	return goal, nil
}

func validateGoal(goal InvestigationGoal, catalog []graph.RelationshipSchema, selectors []graph.AssetSearchSchema) error {
	if goal.Subject.UsesOrganizationResolution() {
		if err := goal.Subject.OrganizationQuery().Validate(); err != nil {
			return err
		}
	} else {
		if err := goal.Subject.AssetSelector().Validate(selectors); err != nil {
			return err
		}
		if goal.Subject.Name != "" || goal.Subject.LegalName != "" || goal.Subject.UniqueID != "" ||
			goal.Subject.RegistrationID != "" || goal.Subject.Jurisdiction != "" {
			return errors.New("typed subject selector cannot mix organization-specific identifiers")
		}
	}
	if goal.Direction != "both" && goal.Direction != "in" && goal.Direction != "out" {
		return errors.New("direction must be both, in, or out")
	}
	if goal.Purpose != "connected" && goal.Purpose != "ultimate_parent" {
		return errors.New("purpose must be connected or ultimate_parent")
	}

	allowed := map[string]bool{}
	for _, s := range selectors {
		allowed[s.Type] = true
	}
	for _, r := range catalog {
		allowed[r.SourceType] = true
		allowed[r.DestinationType] = true
	}
	if len(goal.TargetTypes) > 64 {
		return errors.New("too many target types")
	}
	if !allowed[goal.Subject.Type] {
		return fmt.Errorf("unknown OAM subject type %q", goal.Subject.Type)
	}
	for _, kind := range goal.TargetTypes {
		if !allowed[kind] {
			return fmt.Errorf("unknown OAM target type %q", kind)
		}
	}
	if err := validGoalRelations(goal.Relationships, goal.PathRule, catalog); err != nil {
		return err
	}
	if goal.Purpose == "ultimate_parent" {
		if len(goal.TargetTypes) != 1 || goal.TargetTypes[0] != "Organization" {
			return errors.New("ultimate_parent requires Organization targets")
		}
		if goal.Direction != "both" {
			return errors.New("ultimate_parent requires bidirectional graph exploration")
		}
	}

	return nil
}

// The LLM selects user-provided identifiers and desired output types; the
// graph database, not the model, determines the actual relationships.
func (a Agent) planGoal(ctx context.Context, question string) (InvestigationGoal, error) {
	goal, _, err := a.planGoalCorrected(ctx, question)
	return goal, err
}

// planGoalCorrected plans a goal and also returns why each rejected plan
// was rejected.
func (a Agent) planGoalCorrected(ctx context.Context, question string) (InvestigationGoal, []string, error) {
	var zero InvestigationGoal
	var corrections []string
	sc, ok := a.Runner.Catalog.(graph.AssetSearchCatalog)
	if !ok {
		return zero, nil, errors.New("OAM indexed selector catalog is required")
	}

	selectors := sc.SearchFields()
	relations := a.Runner.Catalog.Relations()
	// The first attempts show only the catalog slice the question mentions;
	// the last attempt shows the whole catalog in case the slice was too
	// narrow. Validation always uses the whole catalog.
	owned := lens.OwnedTypes(a.Runner.Catalog)
	prompt := goalPlannerPrompt(question, relations, selectors, true, owned)
	explicit, explicitHint, schema := prompt.Explicit, prompt.Hint, prompt.Schema
	history := []llm.Message{{Role: "system", Text: prompt.Text}, {Role: "user", Text: question}}
	for attempt := 0; attempt < 3; attempt++ {
		response, err := generateJSON(ctx, a.Model, history, schema)
		if err != nil {
			return zero, corrections, err
		}

		goal, err := parseGoal(response.Text, selectors)
		if err == nil && !explicit && (!prompt.NamesRelationship || goal.Purpose == "ultimate_parent") {
			// The user asked for no particular relationships, so any the model
			// added are its own guesses: they could only narrow the search, and
			// an invalid one would reject an otherwise valid plan. Drop them.
			goal.Relationships, goal.PathRule = nil, ""
		}
		if err == nil && explicit {
			// Validate selectors, target types, traversal direction and purpose
			// before replacing any hallucinated relationship list. An invalid
			// subject or invented target cannot be repaired using schema grounding.
			base := goal
			base.Relationships = nil
			base.PathRule = ""
			if baseErr := validateGoal(base, relations, selectors); baseErr != nil {
				err = baseErr
			} else if repaired, ok := applyExplicitRelationGrounding(base, explicitHint, relations); ok {
				goal = repaired
			} else {
				// No unique OAM schema path satisfies all explicitly named labels.
				// Do not silently drop user constraints or accept an unrelated path.
				err = fmt.Errorf("explicit relationship labels %q have no unique schema path from %s to %v",
					strings.Join(explicitHint.Labels, ", "), base.Subject.Type, base.TargetTypes)
			}
		}
		if err == nil {
			err = validateGoal(goal, relations, selectors)
		}

		narrow := false
		if err == nil {
			goal = repairRowType(goal, question, a.Runner.Catalog)
			goal.Columns = lens.RepairColumns(goal.Columns)
			err = validateAnswer(goal, a.Runner.Catalog)
			narrow = err != nil
		}
		if err == nil {
			return goal, corrections, nil
		}

		corrections = append(corrections, err.Error())
		if attempt == 2 {
			return zero, corrections, fmt.Errorf("invalid investigation goal after 3 attempts: %w", err)
		}

		history = append(history, llm.Message{Role: "assistant", Text: response.Text},
			llm.Message{Role: "user", Text: goalCorrection(err, goal.Subject, selectors)})
		if attempt == 1 && prompt.Sliced {
			full := goalPlannerPrompt(question, relations, selectors, false, owned)
			history[0].Text, schema = full.Text, full.Schema
		}
		if k, ok := answerKind(goal.Answer); narrow && ok && (k.Name == lens.LensTable || k.Name == AnswerHierarchy) {
			// The model chose a table or listing but filled it in wrongly: keep
			// the kind and constrain the retry to what it accepts. Other kinds
			// keep the full schema, because their rejection may mean the question
			// needs another kind.
			schema = narrowGoalSchema(schema, k, a.Runner.Catalog)
		}
	}

	return zero, corrections, errors.New("goal planner exhausted attempts")
}

// goalCorrection tells the planner why its goal was rejected and how to fix
// it, with selector-specific advice when the subject was the problem.
func goalCorrection(err error, subject PlanSubject, selectors []graph.AssetSearchSchema) string {
	msg := "Goal rejected: " + err.Error() + ". Re-read the user's actual question; honor explicitly " +
		"named relationship labels rather than unrelated registration/WHOIS edges. Correct subject and " +
		"target types from the catalog."
	if strings.Contains(err.Error(), `unknown field "fields"`) {
		msg += " You returned an unsupported key named fields. The subject must use singular field and " +
			"value strings, not a fields array or catalog object."
	}
	if subject.Type != "" && !subject.UsesOrganizationResolution() && (subject.Field == "" || subject.Value == "") &&
		subject.EntityID == "" {
		msg += " " + selectorCorrectionHint(subject, selectors)
	}

	return msg + " Return only the full JSON object (subject, target_types, direction, purpose, " +
		"relationships, path_rule, answer, columns)."
}

// AskAdaptive is read-only. It compiles the question into a Query (using a
// deterministic compiler when the wording is narrow and explicit, otherwise
// the model goal planner) and executes it with AskQuery.
func (a Agent) AskAdaptive(ctx context.Context, question string, opts AdaptiveOptions) (out Investigation, err error) {
	a, meter := a.metered()
	defer func() {
		if meter != nil {
			out.Usage = meter.Snapshot()
		}
	}()
	if a.Model == nil || a.Runner.Graph == nil || a.Runner.Catalog == nil {
		return out, errors.New("model, graph, and OAM catalog required")
	}
	if strings.TrimSpace(question) == "" {
		return out, errors.New("question required")
	}
	if err := a.Runner.Limits.Validate(); err != nil {
		return out, err
	}

	planStarted := time.Now()
	var q Query
	q, err = a.CompileQuestion(ctx, question)
	if err != nil {
		out.Incomplete = true
		out.recordTrace(planStarted,
			InvestigationTraceEvent{Stage: "goal_planning", Incomplete: true, Detail: err.Error()})
		return out, err
	}

	planningMode := "model_interpretation"
	if q.Source != SourceModelGoal {
		planningMode = "deterministic_schema_grounding"
	}

	if len(q.PlanCorrections) > 0 {
		planningMode += "; rejected plans: " + strings.Join(q.PlanCorrections, " | ")
	}

	out.recordTrace(planStarted, InvestigationTraceEvent{Stage: "goal_planning", Detail: planningMode})
	return a.executeQuery(ctx, q, opts, out)
}

// thirdPartyLens answers a third_party lens query from root.
func (a Agent) thirdPartyLens(ctx context.Context, root graph.Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	var report lens.ThirdPartyReport
	var err error
	if root.Type == "FQDN" {
		// A domain gets the full vendors lens: the services its TXT records
		// name, and its institution and affiliates set apart.
		report, err = lens.FindVendors(ctx, a.Runner.Graph, a.Runner.Catalog, root,
			lens.VendorOptions{KnownVerification: a.Runner.KnownVerification, Limits: a.Runner.LensLimits})
	} else {
		report, err = lens.SearchThirdPartiesWithin(ctx, a.Runner.Graph, a.Runner.Catalog, root, a.Runner.LensLimits)
	}

	out.recordTrace(started, InvestigationTraceEvent{Stage: "third_party_lens", OutputPaths: len(report.Vendors),
		GraphNodes: report.Footprint, Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.ThirdPartyReport = &report
	out.Incomplete = report.Truncated
	out.Answer = lens.ThirdPartyAnswer(report)
	if root.Type == "FQDN" {
		out.Answer = strings.TrimRight(lens.FormatVendorReport(report), "\n")
	}

	return out, nil
}
