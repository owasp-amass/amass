// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/ai/mcp"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/asset-db/repository"
)

// runEnv is what an amass ai operation runs with: its resolved options, the
// configuration, the model (nil when none is set or the operation uses none)
// and its input and output.
type runEnv struct {
	o        *runOptions
	cfg      *config.Config
	provider llm.Model
	in       io.Reader
	out      io.Writer
	errout   io.Writer
	// journal is the review journal, kept in the database when it keeps
	// one; nil when none is configured.
	journal *review.Journal
}

// plan compiles a question into a query. It reads only the static OAM
// catalog, never the Asset Database, so no database is opened.
func (e *runEnv) plan() error {
	if e.o.question == "" {
		return errors.New("-question required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.o.investigationTimeout)
	defer cancel()
	agent := ai.Agent{
		Model:  e.provider,
		Runner: ai.ToolRunner{Limits: graph.DefaultLimits(), Catalog: oamrepo.Catalog{}},
	}
	q, err := agent.CompileQuestion(ctx, e.o.question)
	if err != nil {
		return err
	}

	return writeJSON(e.out, q)
}

// configAssist has the model suggest a configuration. It reads the schema,
// the current file and the model; it never opens the Asset Database.
func (e *runEnv) configAssist() error {
	if e.provider == nil {
		return errors.New("-model required: config asks the model to suggest a configuration")
	}
	if e.o.question == "" {
		return errors.New("-question required: describe the configuration you want")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.o.investigationTimeout)
	defer cancel()
	return configAssist(ctx, e.in, e.out, e.errout, e.provider, e.o.configPath, e.o.question, e.o.applyConfig)
}

// review asks the model for advice on pending proposals.
func (e *runEnv) review() error {
	if e.provider == nil {
		return errors.New("-model required: review asks the model for advice on pending proposals")
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.o.investigationTimeout)
	defer cancel()
	return reviewProposals(ctx, ai.Agent{Model: e.provider}, e.o.modelName, e.journal, e.o.proposalID,
		e.o.scanLimit, e.out)
}

// loadAliases reads the optional organization aliases file.
func loadAliases(path string) ([]graph.OrganizationAlias, error) {
	if path == "" {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open organization aliases: %w", err)
	}

	aliases, err := graph.LoadOrganizationAliases(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("load organization aliases: %w", err)
	}
	return aliases, nil
}

// readDocuments has the document model read a domain's or organization's
// documents, or undoes a reading. The document model's findings are read as
// stored, so it gets a graph that does not withhold them; no other model is
// given this graph.
func (e *runEnv) readDocuments(repo repository.Repository, aliases []graph.OrganizationAlias) error {
	o := e.o
	dg := oamrepo.New(repo, e.cfg)
	dg.Aliases = aliases
	j := e.journal
	if o.docUndo != "" {
		if err := review.UndoDocumentStatements(context.Background(), repo, j, o.docUndo, "cli"); err != nil {
			return err
		}
		_, err := fmt.Fprintf(e.out, "undid %s\n", o.docUndo)
		return err
	}

	docs := o.effective.Documents
	dm, modelID, timeout, err := ai.DocumentModel(docs)
	if err != nil {
		return err
	}
	for _, w := range ai.DocumentContextWarnings(context.Background(), docs) {
		_, _ = fmt.Fprintln(e.errout, "document model:", w)
	}
	root, err := ai.DocumentRoot(context.Background(), dg, o.docDomain, o.docOrg)
	if err != nil {
		return err
	}
	docRun, err := ai.ReadDocuments(context.Background(), dg, repo, j, root, ai.DocumentRunOptions{Model: dm,
		ModelID: modelID, ModelTimeout: timeout, Pages: ai.DocumentPages(docs, dm), ChunkChars: docs.ChunkChars,
		Max: o.docMax, MaxChunks: docs.MaxChunks, DocumentTimeout: docs.DocumentTimeoutDuration(),
		Reread: o.docReread, DryRun: o.docDryRun})
	if werr := writeDocumentRun(e.out, graph.AssetLabel(root), docRun); werr != nil && err == nil {
		err = werr
	}
	return err
}

// serveMCP serves the MCP tools on stdio: a long-running service, not a
// bounded investigation.
func (e *runEnv) serveMCP(runner ai.ToolRunner, g oamrepo.Adapter) error {
	server := mcp.Server{Runner: runner, ConfigFile: e.o.configPath}
	if e.o.mcpOperator {
		// Whoever can start this process may act: stdio has no token.
		op, release, err := mcp.NewOperator(e.cfg, g, mcp.OperatorOptions{Dir: e.o.dir, ConfigFile: e.o.configPath,
			RunJournal:          os.Getenv("AMASS_MCP_RUN_JOURNAL"),
			RequireConfirmation: os.Getenv("AMASS_MCP_REQUIRE_CONFIRMATION") == "true"})
		if err != nil {
			return fmt.Errorf("operator mode: %w", err)
		}

		defer release()
		server.Operator = op
	}

	return server.Serve(context.Background(), e.in, e.out)
}

// eval measures the configured model against the Asset Database.
func (e *runEnv) eval(runner ai.ToolRunner) error {
	if e.provider == nil {
		return errors.New("-model required: eval measures the configured model against the Asset Database")
	}

	cases, err := loadEvalCases(e.o.evalPath)
	if err != nil {
		return err
	}

	results := (ai.Agent{Model: e.provider, Runner: runner}).RunEvalLive(context.Background(), cases,
		e.o.investigationTimeout, e.o.adaptive())
	if e.o.explicit["format"] && e.o.outputFormat == "json" {
		b, err := ai.MarshalEvalResults(results)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(e.out, string(b)); err != nil {
			return err
		}
	} else if _, err := fmt.Fprint(e.out, ai.FormatEvalResults(results)); err != nil {
		return err
	}
	for _, r := range results {
		if !r.Pass {
			return errors.New("one or more evaluation cases failed")
		}
	}

	return nil
}

// classifier is the classifier of observed OAM evidence: the deterministic
// rules by default; a trained local artifact or an independent service can
// replace them without selecting an LLM.
func (o *runOptions) classifier() (classify.Classifier, error) {
	if o.classifierEndpoint != "" && o.classifierPath != "" {
		return nil, errors.New("choose either classifier service endpoint or local model file")
	}
	if o.classifierEndpoint != "" {
		if err := validateClassifierEndpoint(o.classifierEndpoint); err != nil {
			return nil, err
		}

		return classify.HTTPClient{
			Endpoint: o.classifierEndpoint,
			Client:   &http.Client{Timeout: 10 * time.Second},
		}, nil
	}
	if o.classifierPath != "" {
		raw, err := os.ReadFile(o.classifierPath)
		if err != nil {
			return nil, err
		}

		model, err := classify.Load(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("load local classifier: %w", err)
		}
		if model.FeatureVersion != ai.OrganizationFeatureVersion || model.Task != ai.OrganizationClassificationTask {
			return nil, errors.New("classifier model has incompatible task or feature version")
		}

		return model, nil
	}
	return classify.EvidenceRuleClassifier{}, nil
}

// ask answers a question (adaptive, with the model) or runs a JSON query
// (deterministic routes and hierarchies need no model), then attaches the
// narrative, prints the trace, records the gap proposals and writes the
// answer, as asked.
func (e *runEnv) ask(ctx context.Context, runner ai.ToolRunner) error {
	o := e.o
	agent := ai.Agent{Model: e.provider, Runner: runner}

	var result ai.Investigation
	var err error
	if o.queryPath != "" {
		if o.question != "" {
			return errors.New("use either -question or -query, not both")
		}

		var q ai.Query
		if q, err = readQuery(o.queryPath, e.in); err != nil {
			return err
		}
		result, err = agent.AskQuery(ctx, q, o.adaptive())
	} else {
		if e.provider == nil {
			return errors.New("-model required")
		}
		if o.question == "" {
			return errors.New("-question required")
		}
		result, err = agent.AskAdaptive(ctx, o.question, o.adaptive())
	}
	if err == nil && o.narrate && e.provider != nil {
		err = agent.AttachNarrative(ctx, narrativeQuestion(result), &result)
	}
	if o.showTrace {
		writeTrace(e.errout, result)
	}
	if err != nil {
		return err
	}
	if err := recordGapProposals(e.journal, result, e.errout); err != nil {
		return err
	}

	return writeInvestigation(e.out, o.outputFormat, result)
}

// infer analyzes the candidate in the -candidate file, records it for review
// or as a proposal, and prints the routing.
func (e *runEnv) infer(ctx context.Context, g oamrepo.Adapter, runner ai.ToolRunner,
	localClassifier classify.Classifier) error {
	o := e.o
	if o.candidatePath == "" || e.journal == nil {
		return errors.New("-candidate and -journal required")
	}

	file, err := os.ReadFile(o.candidatePath)
	if err != nil {
		return err
	}

	var c review.Candidate
	if err := json.Unmarshal(file, &c); err != nil {
		return err
	}
	subject, err := g.GetAsset(ctx, c.SubjectID)
	if err != nil {
		return fmt.Errorf("subject missing: %w", err)
	}
	object, err := g.GetAsset(ctx, c.ObjectID)
	if err != nil {
		return fmt.Errorf("object missing: %w", err)
	}

	// Never trust unverified evidence supplied by a file: retrieve evidence
	// for both assets and check each selected ID against the database.
	a, err := g.Evidence(ctx, c.SubjectID, runner.Limits.MaxEvidence)
	if err != nil {
		return err
	}

	b, err := g.Evidence(ctx, c.ObjectID, runner.Limits.MaxEvidence)
	if err != nil {
		return err
	}

	actual := map[string]graph.Evidence{}
	for _, ev := range append(a, b...) {
		actual[ev.ID] = ev
	}

	verified := make([]graph.Evidence, 0, len(c.Evidence))
	for _, ev := range c.Evidence {
		v, ok := actual[ev.ID]
		if !ok {
			return fmt.Errorf("evidence %s not found on candidate endpoints", ev.ID)
		}

		verified = append(verified, v)
	}

	c.Evidence = verified
	// Taxonomy is verified in the CLI in addition to the generic inference layer.
	var allowed []string
	for _, label := range c.AllowedLabels {
		if oamrepo.AllowedRelation(subject.Type, label, object.Type) {
			allowed = append(allowed, label)
		}
	}

	c.AllowedLabels = allowed
	inferrer := ai.Inferrer{Model: e.provider, Plugin: "entity-resolution", ModelID: o.modelName, MinSources: 2}
	routing, err := inferrer.AnalyzeRouted(ctx, c, localClassifier,
		ai.RoutingPolicy{AllowLocalReview: o.classifierReview})
	if err != nil {
		return err
	}

	journal := e.journal
	if routing.Decision == "review" {
		if err := ai.SubmitTriage(journal, c, routing); err != nil {
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

	_, err = fmt.Fprintln(e.out, string(result))
	return err
}
