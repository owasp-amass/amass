// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// runOptions are an amass ai operation's flags, resolved against the
// AMASS_AI_* environment and the configuration's ai section (resolve).
type runOptions struct {
	dir                  string
	configPath           string
	endpoint             string
	providerName         string
	modelName            string
	keyEnv               string
	question             string
	journalPath          string
	candidatePath        string
	classifierPath       string
	classifierEndpoint   string
	aliasesPath          string
	scanLimit            int
	queryPath            string
	evalPath             string
	proposalID           string
	modelOutput          string
	adjudicatorKind      string
	subjectType          string
	subjectField         string
	subjectValue         string
	subjectID            string
	targetTypes          string
	graphDirection       string
	outputFormat         string
	collectionApproval   string
	graphSince           string
	graphDepth           int
	graphMatches         int
	graphAlternates      int
	graphExpansions      int
	guidanceRounds       int
	inventoryNames       int
	modelTimeout         time.Duration
	investigationTimeout time.Duration
	maxTokens            int
	contextTokens        int
	temperatureFlag      string
	think                bool
	showTrace            bool
	narrate              bool
	mcpOperator          bool
	classifierReview     bool
	allowHTTP            bool
	applyConfig          bool
	docDomain            string
	docOrg               string
	docUndo              string
	docMax               int
	docReread            bool
	docDryRun            bool

	// set by resolve
	effective   config.AISettings
	explicit    map[string]bool
	temperature *float64
}

// newRunFlags declares the flags of the amass ai operations.
func newRunFlags(group string, errout io.Writer) (*flag.FlagSet, *runOptions) {
	o := &runOptions{}
	fs := flag.NewFlagSet(group, flag.ContinueOnError)
	fs.SetOutput(errout)
	fs.StringVar(&o.dir, "dir", "", "Amass data directory")
	fs.StringVar(&o.configPath, "config", "", "Amass configuration file")
	fs.StringVar(&o.endpoint, "endpoint", "", "Provider endpoint (defaults depend on provider)")
	fs.BoolVar(&o.allowHTTP, "allow-http", false,
		"Explicitly allow plaintext HTTP inference for a trusted internal endpoint")
	fs.StringVar(&o.providerName, "provider", "compatible",
		"Model provider: ollama (native API), compatible (OpenAI-style) or anthropic")
	fs.StringVar(&o.modelName, "model", "", "Model name; required for ask/infer")
	fs.StringVar(&o.keyEnv, "api-key-env", "AMASS_LLM_API_KEY", "Name of environment variable containing provider key")
	fs.StringVar(&o.question, "question", "", "Natural-language question")
	fs.StringVar(&o.evalPath, "eval-cases", "",
		"Question evaluation set JSON for eval (default: the embedded set of reported questions)")
	fs.StringVar(&o.queryPath, "query", "",
		"JSON Query file to execute with ask (\"-\" reads stdin); route and hierarchy queries need no model")
	fs.StringVar(&o.subjectType, "subject-type", "", "Starting OAM asset type (FQDN, IPAddress, Organization, etc.)")
	fs.StringVar(&o.subjectField, "subject-field", "", "Indexed OAM field used to resolve the subject")
	fs.StringVar(&o.subjectValue, "subject-value", "", "Exact subject identifier")
	fs.StringVar(&o.subjectID, "subject-id", "", "Database entity ID, alternative to indexed subject lookup")
	fs.StringVar(&o.targetTypes, "target-types", "",
		"Comma-separated destination OAM asset types; empty discovers any type")
	fs.StringVar(&o.graphDirection, "direction", "both", "Stored graph edge direction: in, out, or both")
	fs.IntVar(&o.graphDepth, "depth", 0,
		"Maximum path length for graph search (default 16 with target types, otherwise 1)")
	fs.IntVar(&o.graphMatches, "max-matches", 20, "Maximum graph path matches to return")
	fs.IntVar(&o.inventoryNames, "max-names", lens.DefaultInventoryNames,
		"Maximum names listed by an FQDN or subdomain inventory (not sent to the model)")
	fs.IntVar(&o.graphAlternates, "max-paths-per-asset", 3, "Maximum witnessed simple paths retained per asset (1..8)")
	fs.IntVar(&o.graphExpansions, "max-expansions", 0, "Maximum guided path expansions (bounded by global policy)")
	fs.IntVar(&o.guidanceRounds, "guidance-rounds", 2,
		"Maximum intermediate model navigation rounds (0 disables; default 2; max 3)")
	fs.StringVar(&o.graphSince, "since", "", "Only graph edges last seen since this RFC3339 timestamp")
	fs.StringVar(&o.outputFormat, "format", "json",
		"Output format: json, text or mermaid (search); text, json or markdown (signals)")
	fs.StringVar(&o.collectionApproval, "approve-collection", "",
		"Confirmation: the exact plan ID returned by collect-plan for the reviewed scope (not a secret)")
	fs.StringVar(&o.journalPath, "journal", "",
		"Review journal path (default: the attribution journal, review.jsonl in the output directory)")
	fs.StringVar(&o.proposalID, "proposal", "", "Ownership proposal ID to ask model advice on (review)")
	fs.StringVar(&o.modelOutput, "model-output", "",
		"Where train writes the -kind model file (default: the Asset Database when the journal is kept "+
			"there, otherwise the kind's file beside the journal)")
	fs.StringVar(&o.adjudicatorKind, "kind", "",
		"Adjudicator kind for train and status: ownership, horizontal or name_kind (default: every kind)")
	fs.StringVar(&o.candidatePath, "candidate", "", "JSON file with Candidate input for inference")
	fs.StringVar(&o.aliasesPath, "organization-aliases", "",
		"Optional JSON file with explicitly sourced organization alias mappings (read-only)")
	fs.StringVar(&o.classifierPath, "classifier-model", "",
		"Optional local linear model JSON (untrained weights should not be used for production decisions)")
	fs.StringVar(&o.classifierEndpoint, "classifier-endpoint", "",
		"Provider-neutral classifier service URL, e.g., http://classifier:8092")
	fs.BoolVar(&o.classifierReview, "classifier-review", true,
		"Enable default OAM evidence-first classifier review triage; never inserts OAM edges")
	fs.IntVar(&o.scanLimit, "scan-limit", 10, "Maximum candidate pairs to infer, or proposals to review")
	fs.IntVar(&o.maxTokens, "max-tokens", 0,
		"Maximum tokens per model reply (0 = provider default; Anthropic default 4096)")
	fs.StringVar(&o.temperatureFlag, "temperature", "",
		"Model temperature 0..2 (empty = provider default; 0 is most reproducible)")
	fs.IntVar(&o.contextTokens, "context-tokens", 0, "Ollama context window in tokens (0 = 16384)")
	fs.BoolVar(&o.think, "think", false, "Let an Ollama reasoning model think before answering (slower; off by default)")
	fs.BoolVar(&o.showTrace, "trace", false, "Print stage timings and model usage to stderr after ask")
	fs.BoolVar(&o.mcpOperator, "operator", false,
		"mcp: also offer the operator tools (start enumerations, review proposals, manage data sources)")
	fs.BoolVar(&o.applyConfig, "approve-config", false,
		"config: write the suggested configuration to -config without prompting (otherwise it is only shown, or "+
			"you are asked at an interactive terminal)")
	fs.BoolVar(&o.narrate, "narrate", false,
		"After ask, have the model write a short cited summary, verified against the answer's evidence")
	fs.StringVar(&o.docDomain, "domain", "", "read-documents: the domain whose stored documents are read")
	fs.StringVar(&o.docDomain, "d", "", "read-documents: the domain whose stored documents are read (same as -domain)")
	fs.StringVar(&o.docOrg, "org", "", "read-documents: the organization whose stored documents are read")
	fs.IntVar(&o.docMax, "max-documents", 25, "read-documents: most documents the document model reads in one run")
	fs.BoolVar(&o.docReread, "reread", false,
		"read-documents: read documents again even when their version was read, undoing the earlier readings")
	fs.BoolVar(&o.docDryRun, "dry-run", false, "read-documents: read and validate, but store nothing")
	fs.StringVar(&o.docUndo, "undo", "",
		"read-documents: undo a stored reading by its journal ID (doc:...), removing its statements")
	fs.DurationVar(&o.modelTimeout, "model-timeout", 3*time.Minute,
		"Maximum time per model request (e.g., 4m for local Ollama)")
	fs.DurationVar(&o.investigationTimeout, "investigation-timeout", 8*time.Minute,
		"Maximum total time for a single investigation")
	return fs, o
}

// resolve applies the settings the flags did not set explicitly, and checks
// the result.
func (o *runOptions) resolve(fs *flag.FlagSet, cfg *config.Config) error {
	// Settings precedence: explicit flags > AMASS_AI_* environment >
	// YAML ai: section > CLI defaults. No AI service starts implicitly.
	explicitFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicitFlags[f.Name] = true })
	var fileAI config.AISettings
	if cfg.AI != nil {
		fileAI = *cfg.AI
	}

	effective, err := config.ResolveAISettings(fileAI, os.LookupEnv)
	o.effective, o.explicit = effective, explicitFlags
	if err != nil {
		return fmt.Errorf("load AI settings: %w", err)
	}
	if !explicitFlags["provider"] && effective.Provider != "" {
		o.providerName = effective.Provider
	}
	if !explicitFlags["endpoint"] && effective.Endpoint != "" {
		o.endpoint = effective.Endpoint
	}
	if !explicitFlags["model"] && effective.Model != "" {
		o.modelName = effective.Model
	}
	if !explicitFlags["api-key-env"] && effective.APIKeyEnv != "" {
		o.keyEnv = effective.APIKeyEnv
	}
	if !explicitFlags["allow-http"] {
		o.allowHTTP = effective.AllowHTTP
	}
	if !explicitFlags["classifier-model"] && effective.ClassifierModel != "" {
		o.classifierPath = effective.ClassifierModel
	}
	if !explicitFlags["classifier-endpoint"] && effective.ClassifierEndpoint != "" {
		o.classifierEndpoint = effective.ClassifierEndpoint
	}
	if !explicitFlags["classifier-review"] {
		// Keep default-on triage when a YAML ai: section omits this boolean.
		// An explicit environment override or positive YAML value changes it;
		// -classifier-review=false always disables review routing.
		_, fromEnv := os.LookupEnv("AMASS_CLASSIFIER_REVIEW")
		if fromEnv || effective.ClassifierReview {
			o.classifierReview = effective.ClassifierReview
		}
	}
	if !explicitFlags["max-tokens"] && effective.MaxTokens != 0 {
		o.maxTokens = effective.MaxTokens
	}
	if !explicitFlags["temperature"] && effective.Temperature != "" {
		o.temperatureFlag = effective.Temperature
	}
	if !explicitFlags["context-tokens"] && effective.ContextTokens != 0 {
		o.contextTokens = effective.ContextTokens
	}
	if !explicitFlags["think"] {
		o.think = effective.Think
	}
	if o.contextTokens != 0 && (o.contextTokens < 2048 || o.contextTokens > 262144) {
		return errors.New("context tokens must be 0 or 2048..262144")
	}
	if o.maxTokens < 0 || o.maxTokens > 128000 {
		return errors.New("max tokens must be 0..128000")
	}

	o.temperature, err = config.ParseAITemperature(o.temperatureFlag)
	if err != nil {
		return err
	}
	if !explicitFlags["depth"] && effective.MaxDepth != 0 {
		o.graphDepth = effective.MaxDepth
	}
	if !explicitFlags["max-matches"] && effective.MaxMatches != 0 {
		o.graphMatches = effective.MaxMatches
	}
	if !explicitFlags["max-paths-per-asset"] && effective.MaxPathsPerAsset != 0 {
		o.graphAlternates = effective.MaxPathsPerAsset
	}
	if !explicitFlags["max-expansions"] && effective.MaxExpansions != 0 {
		o.graphExpansions = effective.MaxExpansions
	}
	if !explicitFlags["guidance-rounds"] {
		_, fromEnv := os.LookupEnv("AMASS_LLM_GUIDANCE_ROUNDS")
		// only an explicit guidance_rounds overrides the default: another
		// options.ai setting (such as the document model) must not turn
		// guidance off
		if cfg.AIKeySet("guidance_rounds") || fromEnv {
			o.guidanceRounds = effective.GuidanceRounds
		}
	}
	if !explicitFlags["model-timeout"] && effective.ModelTimeout != "" {
		value, err := time.ParseDuration(effective.ModelTimeout)
		if err != nil {
			return err
		}

		o.modelTimeout = value
	}
	if !explicitFlags["investigation-timeout"] && effective.InvestigationTimeout != "" {
		value, err := time.ParseDuration(effective.InvestigationTimeout)
		if err != nil {
			return err
		}

		o.investigationTimeout = value
	}
	if o.modelTimeout < 5*time.Second || o.modelTimeout > 15*time.Minute {
		return errors.New("model timeout must be between 5s and 15m")
	}
	if o.investigationTimeout < o.modelTimeout || o.investigationTimeout > 30*time.Minute {
		return errors.New("investigation timeout must be at least model timeout and at most 30m")
	}
	return nil
}

// adaptive are the graph search bounds of an investigation.
func (o *runOptions) adaptive() ai.AdaptiveOptions {
	return ai.AdaptiveOptions{
		MaxDepth:         o.graphDepth,
		MaxMatches:       o.graphMatches,
		MaxPathsPerAsset: o.graphAlternates,
		MaxExpansions:    o.graphExpansions,
		GuidanceRounds:   o.guidanceRounds,
		MaxInventory:     o.inventoryNames,
	}
}
