// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package cli wires AI functionality to the existing Amass config/database helpers.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/ai/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

const Description = "Read-only AI investigation, MCP tools, and inference proposals"

func CLIWorkflow(_ string, args []string) {
	if err := Run(os.Stdin, os.Stdout, os.Stderr, args); err != nil {
		fmt.Fprintln(os.Stderr, "amass ai:", err)
		os.Exit(1)
	}
}

func Run(in io.Reader, out, errout io.Writer, args []string) error {
	fs := flag.NewFlagSet("ai", flag.ContinueOnError)
	fs.SetOutput(errout)
	var dir, configPath, endpoint, providerName, modelName, keyEnv, question, journalPath, candidatePath, classifierPath, classifierEndpoint, aliasesPath string
	var scanLimit int
	var queryPath string
	var subjectType, subjectField, subjectValue, subjectID, targetTypes, graphDirection, outputFormat, collectionApproval, graphSince string
	var graphDepth, graphMatches, graphAlternates, graphExpansions, guidanceRounds, inventoryNames int
	var modelTimeout, investigationTimeout time.Duration
	var maxTokens, contextTokens int
	var temperatureFlag string
	var think, showTrace bool
	var classifierReview, allowHTTP bool
	fs.StringVar(&dir, "dir", "", "Amass data directory")
	fs.StringVar(&configPath, "config", "", "Amass configuration file")
	fs.StringVar(&endpoint, "endpoint", "", "Provider endpoint (defaults depend on provider)")
	fs.BoolVar(&allowHTTP, "allow-http", false,
		"Explicitly allow plaintext HTTP inference for a trusted internal endpoint")
	fs.StringVar(&providerName, "provider", "compatible",
		"Model provider: ollama (native API), compatible (OpenAI-style) or anthropic")
	fs.StringVar(&modelName, "model", "", "Model name; required for ask/infer")
	fs.StringVar(&keyEnv, "api-key-env", "AMASS_AI_API_KEY", "Name of environment variable containing provider key")
	fs.StringVar(&question, "question", "", "Natural-language question")
	fs.StringVar(&queryPath, "query", "",
		"JSON Query file to execute with ask (\"-\" reads stdin); route and hierarchy queries need no model")
	fs.StringVar(&subjectType, "subject-type", "", "Starting OAM asset type (FQDN, IPAddress, Organization, etc.)")
	fs.StringVar(&subjectField, "subject-field", "", "Indexed OAM field used to resolve the subject")
	fs.StringVar(&subjectValue, "subject-value", "", "Exact subject identifier")
	fs.StringVar(&subjectID, "subject-id", "", "Database entity ID, alternative to indexed subject lookup")
	fs.StringVar(&targetTypes, "target-types", "",
		"Comma-separated destination OAM asset types; empty discovers any type")
	fs.StringVar(&graphDirection, "direction", "both", "Stored graph edge direction: in, out, or both")
	fs.IntVar(&graphDepth, "depth", 0,
		"Maximum path length for graph search (default 16 with target types, otherwise 1)")
	fs.IntVar(&graphMatches, "max-matches", 20, "Maximum graph path matches to return")
	fs.IntVar(&inventoryNames, "max-names", ai.DefaultInventoryNames,
		"Maximum names listed by an FQDN or subdomain inventory (not sent to the model)")
	fs.IntVar(&graphAlternates, "max-paths-per-asset", 3, "Maximum witnessed simple paths retained per asset (1..8)")
	fs.IntVar(&graphExpansions, "max-expansions", 0, "Maximum guided path expansions (bounded by global policy)")
	fs.IntVar(&guidanceRounds, "guidance-rounds", 2,
		"Maximum intermediate model navigation rounds (0 disables; default 2; max 3)")
	fs.StringVar(&graphSince, "since", "", "Only graph edges last seen since this RFC3339 timestamp")
	fs.StringVar(&outputFormat, "format", "json", "Search format: json, text, or mermaid")
	fs.StringVar(&collectionApproval, "approve-collection", "",
		"Confirmation: the exact plan ID returned by collect-plan for the reviewed scope (not a secret)")
	fs.StringVar(&journalPath, "journal", "", "Inference proposal journal path")
	fs.StringVar(&candidatePath, "candidate", "", "JSON file with Candidate input for inference")
	fs.StringVar(&aliasesPath, "organization-aliases", "",
		"Optional JSON file with explicitly sourced organization alias mappings (read-only)")
	fs.StringVar(&classifierPath, "classifier-model", "",
		"Optional local linear model JSON (untrained weights should not be used for production decisions)")
	fs.StringVar(&classifierEndpoint, "classifier-endpoint", "",
		"Provider-neutral classifier service URL, e.g., http://classifier:8092")
	fs.BoolVar(&classifierReview, "classifier-review", true,
		"Enable default OAM evidence-first classifier review triage; never inserts OAM edges")
	fs.IntVar(&scanLimit, "scan-limit", 10, "Maximum candidate pairs to infer")
	fs.IntVar(&maxTokens, "max-tokens", 0,
		"Maximum tokens per model reply (0 = provider default; Anthropic default 4096)")
	fs.StringVar(&temperatureFlag, "temperature", "",
		"Model temperature 0..2 (empty = provider default; 0 is most reproducible)")
	fs.IntVar(&contextTokens, "context-tokens", 0, "Ollama context window in tokens (0 = 8192)")
	fs.BoolVar(&think, "think", false, "Let an Ollama reasoning model think before answering (slower; off by default)")
	fs.BoolVar(&showTrace, "trace", false, "Print stage timings and model usage to stderr after ask")
	fs.DurationVar(&modelTimeout, "model-timeout", 3*time.Minute,
		"Maximum time per model request (e.g., 4m for local Ollama)")
	fs.DurationVar(&investigationTimeout, "investigation-timeout", 8*time.Minute,
		"Maximum total time for a single investigation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: amass ai [flags] ask|plan|mcp|infer|scan|search|collect-plan|collect")
	}

	operation := fs.Arg(0)
	if operation != "ask" && operation != "plan" && operation != "mcp" && operation != "infer" &&
		operation != "scan" && operation != "search" && operation != "collect-plan" && operation != "collect" {
		return fmt.Errorf("unknown operation %q", operation)
	}

	cfg := config.NewConfig()
	if err := config.AcquireConfig(dir, configPath, cfg); err != nil && configPath != "" {
		return fmt.Errorf("load Amass config: %w", err)
	}

	// Settings precedence: explicit flags > AMASS_AI_* environment >
	// YAML ai: section > CLI defaults. No AI service starts implicitly.
	explicitFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicitFlags[f.Name] = true })
	var fileAI config.AISettings
	if cfg.AI != nil {
		fileAI = *cfg.AI
	}

	effective, err := config.ResolveAISettings(fileAI, os.LookupEnv)
	if err != nil {
		return fmt.Errorf("load AI settings: %w", err)
	}
	if !explicitFlags["provider"] && effective.Provider != "" {
		providerName = effective.Provider
	}
	if !explicitFlags["endpoint"] && effective.Endpoint != "" {
		endpoint = effective.Endpoint
	}
	if !explicitFlags["model"] && effective.Model != "" {
		modelName = effective.Model
	}
	if !explicitFlags["api-key-env"] && effective.APIKeyEnv != "" {
		keyEnv = effective.APIKeyEnv
	}
	if !explicitFlags["allow-http"] {
		allowHTTP = effective.AllowHTTP
	}
	if !explicitFlags["classifier-model"] && effective.ClassifierModel != "" {
		classifierPath = effective.ClassifierModel
	}
	if !explicitFlags["classifier-endpoint"] && effective.ClassifierEndpoint != "" {
		classifierEndpoint = effective.ClassifierEndpoint
	}
	if !explicitFlags["classifier-review"] {
		// Keep default-on triage when a YAML ai: section omits this boolean.
		// An explicit environment override or positive YAML value changes it;
		// -classifier-review=false always disables review routing.
		_, fromEnv := os.LookupEnv("AMASS_AI_CLASSIFIER_REVIEW")
		if fromEnv || effective.ClassifierReview {
			classifierReview = effective.ClassifierReview
		}
	}
	if !explicitFlags["max-tokens"] && effective.MaxTokens != 0 {
		maxTokens = effective.MaxTokens
	}
	if !explicitFlags["temperature"] && effective.Temperature != "" {
		temperatureFlag = effective.Temperature
	}
	if !explicitFlags["context-tokens"] && effective.ContextTokens != 0 {
		contextTokens = effective.ContextTokens
	}
	if !explicitFlags["think"] {
		think = effective.Think
	}
	if contextTokens != 0 && (contextTokens < 2048 || contextTokens > 262144) {
		return errors.New("context tokens must be 0 or 2048..262144")
	}
	if maxTokens < 0 || maxTokens > 128000 {
		return errors.New("max tokens must be 0..128000")
	}

	temperature, err := config.ParseAITemperature(temperatureFlag)
	if err != nil {
		return err
	}
	if !explicitFlags["depth"] && effective.MaxDepth != 0 {
		graphDepth = effective.MaxDepth
	}
	if !explicitFlags["max-matches"] && effective.MaxMatches != 0 {
		graphMatches = effective.MaxMatches
	}
	if !explicitFlags["max-paths-per-asset"] && effective.MaxPathsPerAsset != 0 {
		graphAlternates = effective.MaxPathsPerAsset
	}
	if !explicitFlags["max-expansions"] && effective.MaxExpansions != 0 {
		graphExpansions = effective.MaxExpansions
	}
	if !explicitFlags["guidance-rounds"] {
		_, fromEnv := os.LookupEnv("AMASS_AI_GUIDANCE_ROUNDS")
		if cfg.AI != nil || fromEnv {
			guidanceRounds = effective.GuidanceRounds
		}
	}
	if !explicitFlags["model-timeout"] && effective.ModelTimeout != "" {
		value, err := time.ParseDuration(effective.ModelTimeout)
		if err != nil {
			return err
		}

		modelTimeout = value
	}
	if !explicitFlags["investigation-timeout"] && effective.InvestigationTimeout != "" {
		value, err := time.ParseDuration(effective.InvestigationTimeout)
		if err != nil {
			return err
		}

		investigationTimeout = value
	}
	if modelTimeout < 5*time.Second || modelTimeout > 15*time.Minute {
		return errors.New("model timeout must be between 5s and 15m")
	}
	if investigationTimeout < modelTimeout || investigationTimeout > 30*time.Minute {
		return errors.New("investigation timeout must be at least model timeout and at most 30m")
	}

	// Only plan, ask, infer and scan can use a model, and plan and ask can
	// run deterministic queries without one. MCP, search and collection never
	// build a model client, so a model setting cannot break them.
	usesModel := operation == "plan" || operation == "ask" || operation == "infer" || operation == "scan"
	var provider ai.Model
	if usesModel && modelName != "" {
		var err error
		provider, err = newProvider(providerSettings{Provider: providerName, Endpoint: endpoint, Model: modelName,
			APIKey: os.Getenv(keyEnv), AllowHTTP: allowHTTP, Timeout: modelTimeout, MaxTokens: maxTokens,
			ContextTokens: contextTokens, Temperature: temperature, Think: think})
		if err != nil {
			return err
		}
	}
	if operation == "plan" {
		// Compiling a question reads only the static OAM catalog, never the
		// Asset Database, so no database is opened.
		if question == "" {
			return errors.New("-question required")
		}

		ctx, cancel := context.WithTimeout(context.Background(), investigationTimeout)
		defer cancel()
		agent := ai.Agent{
			Model:  provider,
			Runner: ai.ToolRunner{Limits: ai.DefaultLimits(), Catalog: oamrepo.Catalog{}},
		}
		q, err := agent.CompileQuestion(ctx, question)
		if err != nil {
			return err
		}

		return writeJSON(out, q)
	}

	repo := tools.OpenGraphDatabase(cfg)
	if repo == nil {
		return errors.New("unable to open OAM database")
	}

	defer repo.Close()
	var aliases []ai.OrganizationAlias
	if aliasesPath != "" {
		f, err := os.Open(aliasesPath)
		if err != nil {
			return fmt.Errorf("open organization aliases: %w", err)
		}

		aliases, err = ai.LoadOrganizationAliases(f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("load organization aliases: %w", err)
		}
	}

	graph := oamrepo.Adapter{Repo: repo, Aliases: aliases, Neo4jDatabase: oamrepo.Neo4jDatabaseName(cfg)}
	runner := ai.ToolRunner{Graph: graph, Limits: ai.DefaultLimits(), Catalog: oamrepo.Catalog{}}
	ctx, cancel := context.WithTimeout(context.Background(), investigationTimeout)
	defer cancel()
	if operation == "mcp" {
		// MCP is a long-running stdio service, not a 2-minute investigation.
		cancel()
		return (mcp.Server{Runner: runner}).Serve(context.Background(), in, out)
	}
	if operation == "search" {
		return graphSearch(ctx, runner, graphSearchOptions{
			SubjectType: subjectType, SubjectField: subjectField, SubjectValue: subjectValue,
			SubjectID: subjectID, TargetTypes: targetTypes, Direction: graphDirection,
			MaxDepth: graphDepth, MaxMatches: graphMatches, Since: graphSince, Format: outputFormat,
		}, out)
	}
	if operation == "collect-plan" || operation == "collect" {
		if subjectID != "" || subjectType == "" || subjectField == "" || subjectValue == "" {
			return errors.New("collection requires exact -subject-type, -subject-field and -subject-value (not -subject-id)")
		}

		plan := ai.PlanCollection(ai.AssetSelector{Type: subjectType, Field: subjectField, Value: subjectValue})
		return collectTarget(ctx, cfg, plan, collectionApproval, operation == "collect", out)
	}

	// Default to deterministic classification of observed OAM evidence; a trained
	// local artifact or independent service can replace it without selecting an LLM.
	var localClassifier classify.Classifier = classify.EvidenceRuleClassifier{}
	if classifierEndpoint != "" && classifierPath != "" {
		return errors.New("choose either classifier service endpoint or local model file")
	}
	if classifierEndpoint != "" {
		if err := validateClassifierEndpoint(classifierEndpoint); err != nil {
			return err
		}

		localClassifier = classify.HTTPClient{
			Endpoint: classifierEndpoint,
			Client:   &http.Client{Timeout: 10 * time.Second},
		}
	}
	if classifierPath != "" {
		raw, err := os.ReadFile(classifierPath)
		if err != nil {
			return err
		}

		model, err := classify.Load(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("load local classifier: %w", err)
		}
		if model.FeatureVersion != ai.OrganizationFeatureVersion || model.Task != ai.OrganizationClassificationTask {
			return errors.New("classifier model has incompatible task or feature version")
		}

		localClassifier = model
	}
	if operation == "ask" && queryPath != "" {
		if question != "" {
			return errors.New("use either -question or -query, not both")
		}

		q, err := readQuery(queryPath, in)
		if err != nil {
			return err
		}

		result, err := (ai.Agent{Model: provider, Runner: runner}).AskQuery(ctx, q,
			ai.AdaptiveOptions{
				MaxDepth:         graphDepth,
				MaxMatches:       graphMatches,
				MaxPathsPerAsset: graphAlternates,
				MaxExpansions:    graphExpansions,
				GuidanceRounds:   guidanceRounds,
				MaxInventory:     inventoryNames,
			})
		if showTrace {
			writeTrace(errout, result)
		}
		if err != nil {
			return err
		}

		return writeInvestigation(out, outputFormat, result)
	}
	if provider == nil {
		return errors.New("-model required")
	}
	switch operation {
	case "scan":
		return scan(ctx, graph, provider, modelName, journalPath, scanLimit, localClassifier, classifierReview, out)
	case "ask":
		if question == "" {
			return errors.New("-question required")
		}

		result, err := (ai.Agent{Model: provider, Runner: runner}).AskAdaptive(ctx, question,
			ai.AdaptiveOptions{
				MaxDepth:         graphDepth,
				MaxMatches:       graphMatches,
				MaxPathsPerAsset: graphAlternates,
				MaxExpansions:    graphExpansions,
				GuidanceRounds:   guidanceRounds,
				MaxInventory:     inventoryNames,
			})
		if showTrace {
			writeTrace(errout, result)
		}
		if err != nil {
			return err
		}

		return writeInvestigation(out, outputFormat, result)
	case "infer":
		if candidatePath == "" || journalPath == "" {
			return errors.New("-candidate and -journal required")
		}

		file, err := os.ReadFile(candidatePath)
		if err != nil {
			return err
		}

		var c ai.Candidate
		if err := json.Unmarshal(file, &c); err != nil {
			return err
		}
		if _, err := graph.GetAsset(ctx, c.SubjectID); err != nil {
			return fmt.Errorf("subject missing: %w", err)
		}
		if _, err := graph.GetAsset(ctx, c.ObjectID); err != nil {
			return fmt.Errorf("object missing: %w", err)
		}

		// Never trust unverified evidence supplied by a file: retrieve evidence
		// for both assets and check each selected ID against the database.
		a, err := graph.Evidence(ctx, c.SubjectID, runner.Limits.MaxEvidence)
		if err != nil {
			return err
		}

		b, err := graph.Evidence(ctx, c.ObjectID, runner.Limits.MaxEvidence)
		if err != nil {
			return err
		}

		actual := map[string]ai.Evidence{}
		for _, e := range append(a, b...) {
			actual[e.ID] = e
		}

		verified := make([]ai.Evidence, 0, len(c.Evidence))
		for _, e := range c.Evidence {
			v, ok := actual[e.ID]
			if !ok {
				return fmt.Errorf("evidence %s not found on candidate endpoints", e.ID)
			}

			verified = append(verified, v)
		}

		c.Evidence = verified
		// Taxonomy is verified in the CLI in addition to the generic inference layer.
		subject, err := graph.GetAsset(ctx, c.SubjectID)
		if err != nil {
			return err
		}

		object, err := graph.GetAsset(ctx, c.ObjectID)
		if err != nil {
			return err
		}

		var allowed []string
		for _, label := range c.AllowedLabels {
			if oamrepo.AllowedRelation(subject.Type, label, object.Type) {
				allowed = append(allowed, label)
			}
		}

		c.AllowedLabels = allowed
		inferrer := ai.Inferrer{Model: provider, Plugin: "entity-resolution", ModelID: modelName, MinSources: 2}
		routing, err := inferrer.AnalyzeRouted(ctx, c, localClassifier,
			ai.RoutingPolicy{AllowLocalReview: classifierReview})
		if err != nil {
			return err
		}

		journal := &ai.Journal{Path: journalPath}
		if routing.Decision == "review" {
			if err := journal.SubmitTriage(c, routing); err != nil {
				return err
			}
		}
		if routing.Proposal != nil {
			if err := journal.Submit(*routing.Proposal); err != nil {
				return err
			}
		}

		result, err := json.MarshalIndent(routing, "", "  ")
		if err != nil {
			return err
		}

		_, err = fmt.Fprintln(out, string(result))
		return err
	}

	return nil
}

// validateModelEndpoint prevents accidental plaintext transmission of graph
// evidence. In-container HTTP to Ollama requires explicit opt-in.
func validateModelEndpoint(endpoint string, allowHTTP bool) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid inference endpoint: %w", err)
	}
	if u.User != nil || u.Host == "" || u.Hostname() == "" || u.Fragment != "" {
		return errors.New("inference endpoint must have a hostname and no URL credentials or fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" {
		return errors.New("inference endpoint must use HTTPS or explicitly permitted HTTP")
	}
	if u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" {
		return nil
	}
	if !allowHTTP {
		return errors.New("remote HTTP inference requires explicit -allow-http or AMASS_AI_ALLOW_HTTP=true for a trusted internal endpoint")
	}

	return nil
}

func validateClassifierEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return errors.New("invalid classifier endpoint")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || (u.Hostname() != "classifier" && u.Hostname() != "localhost" &&
		u.Hostname() != "127.0.0.1")) {
		return errors.New("classifier HTTP is permitted only on the trusted Compose service hostname or localhost; otherwise use HTTPS")
	}

	return nil
}
