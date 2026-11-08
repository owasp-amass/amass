// SPDX-License-Identifier: Apache-2.0
// Package cli wires AI functionality to the existing Amass config/database helpers.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai"
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
	var dir, configPath, endpoint, providerName, modelName, keyEnv, question, journalPath, candidatePath string
	var scanLimit int
	fs.StringVar(&dir, "dir", "", "Amass data directory")
	fs.StringVar(&configPath, "config", "", "Amass configuration file")
	fs.StringVar(&endpoint, "endpoint", "", "Provider endpoint (defaults depend on provider)")
	fs.StringVar(&providerName, "provider", "compatible", "Model provider: compatible or anthropic")
	fs.StringVar(&modelName, "model", "", "Model name; required for ask/infer")
	fs.StringVar(&keyEnv, "api-key-env", "AMASS_AI_API_KEY", "Name of environment variable containing provider key")
	fs.StringVar(&question, "question", "", "Natural-language question")
	fs.StringVar(&journalPath, "journal", "", "Inference proposal journal path")
	fs.StringVar(&candidatePath, "candidate", "", "JSON file with Candidate input for inference")
	fs.IntVar(&scanLimit, "scan-limit", 10, "Maximum candidate pairs to infer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: amass ai [flags] ask|mcp|infer|scan")
	}
	operation := fs.Arg(0)
	if operation != "ask" && operation != "mcp" && operation != "infer" && operation != "scan" {
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
	graph := oamrepo.Adapter{Repo: repo}
	runner := ai.ToolRunner{Graph: graph, Limits: ai.DefaultLimits()}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if operation == "mcp" {
		// MCP is a long-running stdio service, not a 2-minute investigation.
		cancel()
		return (mcp.Server{Runner: runner}).Serve(context.Background(), in, out)
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
		provider = ai.CompatibleModel{Endpoint: endpoint, ModelName: modelName, APIKey: os.Getenv(keyEnv)}
	case "anthropic":
		if endpoint == "" {
			endpoint = "https://api.anthropic.com/v1/messages"
		}
		provider = ai.AnthropicModel{Endpoint: endpoint, ModelName: modelName, APIKey: os.Getenv(keyEnv)}
	default:
		return fmt.Errorf("unknown model provider %q", providerName)
	}
	if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://127.0.0.1:") && !strings.HasPrefix(endpoint, "http://localhost:") {
		return errors.New("remote model endpoint must use HTTPS")
	}
	switch operation {
	case "scan":
		return scan(ctx, graph, provider, modelName, journalPath, scanLimit, out)
	case "ask":
		if question == "" {
			return errors.New("-question required")
		}
		result, err := (ai.Agent{Model: provider, Runner: runner}).Ask(ctx, question)
		if err != nil {
			return err
		}
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
		proposal, err := inferrer.Analyze(ctx, c)
		if err != nil {
			return err
		}
		if proposal == nil {
			_, err = fmt.Fprintln(out, "no supported relation proposed")
			return err
		}
		if err := (&ai.Journal{Path: journalPath}).Submit(*proposal); err != nil {
			return err
		}
		result, err := json.MarshalIndent(proposal, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(result))
		return err
	}
	return nil
}
