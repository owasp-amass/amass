// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package cli wires AI functionality to the existing Amass config/database helpers.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/owasp-amass/amass/v5/config"
	dnssd "github.com/owasp-amass/amass/v5/engine/plugins/service_discovery/dns"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	lenscli "github.com/owasp-amass/amass/v5/internal/lens/cli"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

const Description = "Ask questions with a language model, MCP tools, and model-assisted review"

// operations are the amass ai subcommands. The lenses, the database-hygiene
// scans and the review of their proposals are amass lens, amass db and amass
// review (package internal/lens/cli); amass ai still runs them by their old
// names, with a note.
var operations = []string{"ask", "plan", "eval", "mcp", "infer", "scan", "search", "collect-plan", "collect",
	"train", "status", "review", "config", "read-documents"}

func CLIWorkflow(_ string, args []string) {
	if err := Run(os.Stdin, os.Stdout, os.Stderr, args); err != nil {
		fmt.Fprintln(os.Stderr, "amass ai:", err)
		os.Exit(1)
	}
}

// Run runs amass ai. Operations that moved to amass lens, amass db or amass
// review still run, with a note naming the new command.
func Run(in io.Reader, out, errout io.Writer, args []string) error {
	moved := lenscli.Operations()
	for _, at := range []int{0, len(args) - 1} {
		if at < 0 || at >= len(args) {
			continue
		}
		if now, ok := moved[args[at]]; ok {
			_, _ = fmt.Fprintf(errout, "note: amass ai %s is now %s\n", args[at], now)
			rest := append(append([]string{}, args[:at]...), args[at+1:]...)
			return lenscli.RunOperation(args[at], in, out, errout, rest)
		}
	}

	return run("ai", in, out, errout, args)
}

func run(group string, in io.Reader, out, errout io.Writer, args []string) error {
	fs, o := newRunFlags(group, errout)
	// The operation may come first (amass ai family -d owasp.org) or last
	// (amass ai -d owasp.org family).
	if len(args) > 1 && slices.Contains(operations, args[0]) {
		args = append(append([]string{}, args[1:]...), args[0])
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		if group != "ai" {
			return fmt.Errorf("usage: amass %s <name> [flags]; unexpected arguments %v", group, fs.Args())
		}

		return errors.New("usage: amass ai [flags] " + strings.Join(operations, "|"))
	}

	operation := fs.Arg(0)
	if !slices.Contains(operations, operation) {
		return fmt.Errorf("unknown operation %q", operation)
	}

	cfg := config.NewConfig()
	if err := config.AcquireConfig(o.dir, o.configPath, cfg); err != nil && o.configPath != "" {
		return fmt.Errorf("load Amass config: %w", err)
	}
	if err := o.resolve(fs, cfg); err != nil {
		return err
	}

	// Only plan, ask, eval, infer, scan and review can use a model, and plan
	// and ask can run deterministic queries without one. MCP, search,
	// collection and the other proposal operations never build a model
	// client, so a model setting cannot break them.
	usesModel := operation == "plan" || operation == "ask" || operation == "eval" || operation == "infer" ||
		operation == "scan" || operation == "review" || operation == "config"
	var provider llm.Model
	if usesModel && o.modelName != "" {
		var err error
		provider, err = newProvider(providerSettings{Provider: o.providerName, Endpoint: o.endpoint, Model: o.modelName,
			APIKey: strings.TrimSpace(os.Getenv(o.keyEnv)), AllowHTTP: o.allowHTTP, Timeout: o.modelTimeout,
			MaxTokens: o.maxTokens, ContextTokens: o.contextTokens, Temperature: o.temperature, Think: o.think})
		if err != nil {
			return err
		}
	}
	// The review journal defaults to the one automatic attribution uses.
	if o.journalPath == "" {
		_, path, err := cfg.AIAttribution(os.LookupEnv)
		if err != nil {
			return err
		}

		o.journalPath = path
	}

	e := &runEnv{o: o, cfg: cfg, provider: provider, in: in, out: out, errout: errout}
	// These read and append to the journal only: the database's journal when
	// it keeps one, otherwise the file.
	switch operation {
	case "train", "status", "review":
		if repo := tools.OpenGraphDatabase(cfg); repo != nil {
			defer func() { _ = repo.Close() }()
			e.journal = review.OpenJournal(o.journalPath, repo)
		} else {
			e.journal = review.OpenJournal(o.journalPath, nil)
		}
		switch operation {
		case "train":
			return trainAdjudicators(e.journal, o.adjudicatorKind, o.modelOutput, out)
		case "status":
			return adjudicatorStatus(e.journal, o.adjudicatorKind, out)
		}
		return e.review()
	}
	switch operation {
	case "plan":
		return e.plan()
	case "config":
		return e.configAssist()
	}

	repo := tools.OpenGraphDatabase(cfg)
	if repo == nil {
		return errors.New("unable to open OAM database")
	}

	defer func() { _ = repo.Close() }()
	e.journal = review.OpenJournal(o.journalPath, repo)
	aliases, err := loadAliases(o.aliasesPath)
	if err != nil {
		return err
	}
	if operation == "read-documents" {
		return e.readDocuments(repo, aliases)
	}

	// models served here read document text only when the user shares it
	g := oamrepo.New(repo, cfg)
	g.Aliases, g.WithholdDocumentText = aliases, !cfg.AI.DocumentsShared()
	runner := ai.ToolRunner{Graph: g, Limits: graph.DefaultLimits(), Catalog: oamrepo.Catalog{},
		KnownVerification: dnssd.IsVerificationRecord}
	// The ownership-gap answer uses the trained attribution model when one has
	// been trained on the review journal.
	scorer, err := ai.LoadAttributionScorer(e.journal)
	if err != nil {
		return fmt.Errorf("load attribution model: %w", err)
	}
	runner.Attribution = scorer
	if operation == "mcp" {
		return e.serveMCP(runner, g)
	}

	ctx, cancel := context.WithTimeout(context.Background(), o.investigationTimeout)
	defer cancel()
	switch operation {
	case "eval":
		return e.eval(runner)
	case "search":
		return graphSearch(ctx, runner, graphSearchOptions{
			SubjectType: o.subjectType, SubjectField: o.subjectField, SubjectValue: o.subjectValue,
			SubjectID: o.subjectID, TargetTypes: o.targetTypes, Direction: o.graphDirection,
			MaxDepth: o.graphDepth, MaxMatches: o.graphMatches, Since: o.graphSince, Format: o.outputFormat,
		}, out)
	case "collect-plan", "collect":
		if o.subjectID != "" || o.subjectType == "" || o.subjectField == "" || o.subjectValue == "" {
			return errors.New("collection requires exact -subject-type, -subject-field and -subject-value (not -subject-id)")
		}

		plan := ai.PlanCollection(graph.AssetSelector{Type: o.subjectType, Field: o.subjectField,
			Value: o.subjectValue})
		return collectTarget(ctx, cfg, plan, o.collectionApproval, operation == "collect", out)
	}

	localClassifier, err := o.classifier()
	if err != nil {
		return err
	}
	switch operation {
	case "ask":
		return e.ask(ctx, runner)
	case "scan":
		if provider == nil {
			return errors.New("-model required")
		}
		return scan(ctx, g, provider, o.modelName, e.journal, o.scanLimit, localClassifier, o.classifierReview, out)
	case "infer":
		if provider == nil {
			return errors.New("-model required")
		}
		return e.infer(ctx, g, runner, localClassifier)
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

// loadEvalCases reads an evaluation set from path, or the embedded set of
// reported questions when path is empty.
func loadEvalCases(path string) ([]ai.EvalCase, error) {
	if path == "" {
		return ai.DefaultEvalCases()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read evaluation set: %w", err)
	}

	return ai.LoadEvalCases(data)
}

// narrativeQuestion is the question a narrative answers: the user's words,
// or the Query description for a structured Query.
func narrativeQuestion(inv ai.Investigation) string {
	if inv.Query == nil {
		return ""
	}
	if inv.Query.Question != "" {
		return inv.Query.Question
	}

	return inv.Query.Describe()
}
