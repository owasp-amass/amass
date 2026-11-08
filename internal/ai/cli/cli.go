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
	"os"
	"strings"
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
	var dir, configPath, endpoint, providerName, modelName, keyEnv, question, journalPath, candidatePath, classifierPath, aliasesPath string
	var scanLimit int
	var subjectType, subjectField, subjectValue, subjectID, targetTypes, graphDirection, outputFormat, collectionApproval, graphSince string
	var graphDepth, graphMatches int
	var modelTimeout, investigationTimeout time.Duration
	var classifierReview bool
	fs.StringVar(&dir, "dir", "", "Amass data directory")
	fs.StringVar(&configPath, "config", "", "Amass configuration file")
	fs.StringVar(&endpoint, "endpoint", "", "Provider endpoint (defaults depend on provider)")
	fs.StringVar(&providerName, "provider", "compatible", "Model provider: compatible or anthropic")
	fs.StringVar(&modelName, "model", "", "Model name; required for ask/infer")
	fs.StringVar(&keyEnv, "api-key-env", "AMASS_AI_API_KEY", "Name of environment variable containing provider key")
	fs.StringVar(&question, "question", "", "Natural-language question")
	fs.StringVar(&subjectType, "subject-type", "", "Starting OAM asset type (FQDN, IPAddress, Organization, etc.)")
	fs.StringVar(&subjectField, "subject-field", "", "Indexed OAM field used to resolve the subject")
	fs.StringVar(&subjectValue, "subject-value", "", "Exact subject identifier")
	fs.StringVar(&subjectID, "subject-id", "", "Database entity ID, alternative to indexed subject lookup")
	fs.StringVar(&targetTypes, "target-types", "", "Comma-separated destination OAM asset types; empty discovers any type")
	fs.StringVar(&graphDirection, "direction", "both", "Stored graph edge direction: in, out, or both")
	fs.IntVar(&graphDepth, "depth", 0, "Maximum path length for graph search (default 16 with target types, otherwise 1)")
	fs.IntVar(&graphMatches, "max-matches", 20, "Maximum graph path matches to return")
	fs.StringVar(&graphSince, "since", "", "Only graph edges last seen since this RFC3339 timestamp")
	fs.StringVar(&outputFormat, "format", "json", "Search format: json, text, or mermaid")
	fs.StringVar(&collectionApproval, "approve-collection", "", "Explicit approval: exact plan ID returned by collect-plan")
	fs.StringVar(&journalPath, "journal", "", "Inference proposal journal path")
	fs.StringVar(&candidatePath, "candidate", "", "JSON file with Candidate input for inference")
	fs.StringVar(&aliasesPath, "organization-aliases", "", "Optional JSON file with explicitly sourced organization alias mappings (read-only)")
	fs.StringVar(&classifierPath, "classifier-model", "", "Optional local linear model JSON (untrained weights should not be used for production decisions)")
	fs.BoolVar(&classifierReview, "classifier-review", false, "Permit review-only triage without invoking a generative model; never inserts OAM edges")
	fs.IntVar(&scanLimit, "scan-limit", 10, "Maximum candidate pairs to infer")
	fs.DurationVar(&modelTimeout, "model-timeout", 3*time.Minute, "Maximum time per model request (e.g., 4m for local Ollama)")
	fs.DurationVar(&investigationTimeout, "investigation-timeout", 8*time.Minute, "Maximum total time for a single investigation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if modelTimeout < 5*time.Second || modelTimeout > 15*time.Minute {
		return errors.New("-model-timeout must be between 5s and 15m")
	}
	if investigationTimeout < modelTimeout || investigationTimeout > 30*time.Minute {
		return errors.New("-investigation-timeout must be at least -model-timeout and no more than 30m")
	}
	if fs.NArg() != 1 {
		return errors.New("usage: amass ai [flags] ask|mcp|infer|scan|search|collect-plan|collect")
	}
	operation := fs.Arg(0)
	if operation != "ask" && operation != "mcp" && operation != "infer" && operation != "scan" && operation != "search" && operation != "collect-plan" && operation != "collect" {
		return fmt.Errorf("unknown operation %q", operation)
	}
	cfg := config.NewConfig()
	if err := config.AcquireConfig(dir, configPath, cfg); err != nil && configPath != "" {
		return fmt.Errorf("load Amass config: %w", err)
	}
	repo := tools.OpenGraphDatabase(cfg)
	if repo == nil {
		return errors.New("unable to open OAM database")
	}
	defer repo.Close()
	var aliases []ai.OrganizationAlias
	if aliasesPath!="" {
		f,err:=os.Open(aliasesPath)
		if err!=nil{return fmt.Errorf("open organization aliases: %w",err)}
		aliases,err=ai.LoadOrganizationAliases(f)
		_ = f.Close()
		if err!=nil{return fmt.Errorf("load organization aliases: %w",err)}
	}
	graph := oamrepo.Adapter{Repo: repo, Aliases: aliases}
	runner := ai.ToolRunner{Graph: graph, Limits: ai.DefaultLimits(), Catalog: oamrepo.Catalog{}}
	ctx, cancel := context.WithTimeout(context.Background(), investigationTimeout)
	defer cancel()
	if operation == "mcp" {
		// MCP is a long-running stdio service, not a 2-minute investigation.
		cancel()
		return (mcp.Server{Runner: runner}).Serve(context.Background(), in, out)
	}
	if operation=="search" {
		return graphSearch(ctx,runner,graphSearchOptions{
			SubjectType:subjectType,SubjectField:subjectField,SubjectValue:subjectValue,
			SubjectID:subjectID,TargetTypes:targetTypes,Direction:graphDirection,
			MaxDepth:graphDepth,MaxMatches:graphMatches,Since:graphSince,Format:outputFormat,
		},out)
	}
	if operation=="collect-plan" || operation=="collect" {
		if subjectID!="" || subjectType=="" || subjectField=="" || subjectValue=="" {
			return errors.New("collection requires exact -subject-type, -subject-field and -subject-value (not -subject-id)")
		}
		plan:=ai.PlanCollection(ai.AssetSelector{Type:subjectType,Field:subjectField,Value:subjectValue})
		return collectTarget(ctx,cfg,plan,collectionApproval,operation=="collect",out)
	}
	if classifierReview && classifierPath == "" {
		return errors.New("-classifier-review requires -classifier-model")
	}
	var localClassifier classify.Classifier
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
	if modelName == "" {
		return errors.New("-model required")
	}
	var provider ai.Model
	switch providerName {
	case "compatible":
		if endpoint == "" {
			endpoint = "http://127.0.0.1:11434/v1/chat/completions"
		}
		provider = ai.CompatibleModel{Endpoint: endpoint, ModelName: modelName, APIKey: os.Getenv(keyEnv), Client: &http.Client{Timeout: modelTimeout}}
	case "anthropic":
		if endpoint == "" {
			endpoint = "https://api.anthropic.com/v1/messages"
		}
		provider = ai.AnthropicModel{Endpoint: endpoint, ModelName: modelName, APIKey: os.Getenv(keyEnv), Client: &http.Client{Timeout: modelTimeout}}
	default:
		return fmt.Errorf("unknown model provider %q", providerName)
	}
	if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://127.0.0.1:") && !strings.HasPrefix(endpoint, "http://localhost:") {
		return errors.New("remote model endpoint must use HTTPS")
	}
	switch operation {
	case "scan":
		return scan(ctx, graph, provider, modelName, journalPath, scanLimit, localClassifier, classifierReview, out)
	case "ask":
		if question == "" {
			return errors.New("-question required")
		}
		result, err := (ai.Agent{Model: provider, Runner: runner}).AskAdaptive(ctx, question, ai.AdaptiveOptions{MaxDepth:graphDepth,MaxMatches:graphMatches})
		if err != nil {
			return err
		}
		if outputFormat=="text" {
			_, err = fmt.Fprintln(out, result.Answer)
			return err
		}
		if outputFormat=="mermaid" {
			if result.Diagram=="" {return fmt.Errorf("investigation did not produce a diagram: %s",result.Answer)}
			_, err=fmt.Fprint(out,result.Diagram)
			return err
		}
		if outputFormat!="json" {return errors.New("-format must be json, text, or mermaid")}
		pretty, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(pretty))
		return err
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
		routing, err := inferrer.AnalyzeRouted(ctx, c, localClassifier, ai.RoutingPolicy{AllowLocalReview: classifierReview})
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
