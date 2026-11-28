// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/coord"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/secrets"
)

// OperatorOptions configures NewOperator.
type OperatorOptions struct {
	// Dir and ConfigFile load a fresh configuration for each enumeration.
	Dir, ConfigFile string
	// RunJournal records enumeration runs (JSON lines); empty keeps them in
	// memory only. With a database that keeps a journal, runs are kept in
	// its runs topic instead, and a file's runs are moved there once.
	RunJournal string
	// WatchFile keeps scheduled enumerations; empty disables watches. With a
	// database that keeps a journal, they are kept in its watches topic, and
	// a file's watches are moved there once.
	WatchFile string
	// PublicURL is how a user's browser reaches the HTTP server, for
	// data source key links; empty disables them.
	PublicURL           string
	RequireConfirmation bool
	// IdleTimeout and MaxDuration bound enumerations; zero keeps the
	// collect package's defaults.
	IdleTimeout time.Duration
	MaxDuration time.Duration
}

// NewOperator builds the operator tools' dependencies from a loaded
// configuration: an engine client, a supervising enumeration manager that
// resumes earlier runs, the review journal and the datasources file. The
// returned function releases them.
func NewOperator(cfg *config.Config, g oamrepo.Adapter, opts OperatorOptions) (*Operator, func(), error) {
	c, err := client.NewClient(collect.EngineURL(cfg))
	if err != nil {
		return nil, nil, fmt.Errorf("engine API client: %w", err)
	}

	_, journal, err := cfg.AIAttribution(os.LookupEnv)
	if err != nil {
		c.Close()
		return nil, nil, err
	}

	key, err := secrets.LoadKey(os.LookupEnv)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	m := &collect.Manager{
		Engine: c,
		Config: func() (*config.Config, error) {
			fresh := config.NewConfig()
			if err := config.AcquireConfig(opts.Dir, opts.ConfigFile, fresh); err != nil {
				return nil, err
			}

			return fresh, nil
		},
		Journal:     opts.RunJournal,
		RunTopic:    coord.Open(g.Repo, "runs"),
		Leases:      coord.OpenLeases(g.Repo),
		IdleTimeout: opts.IdleTimeout,
		MaxDuration: opts.MaxDuration,
	}
	// options.ai.documents.hold bounds how long a run is kept open for the
	// documents left to read; 0 keeps none open
	hold := collect.DefaultHoldLimit
	if v, ok := cfg.AI.Documents.HoldDuration(); ok {
		hold = v
	}
	if hold == 0 {
		m.HoldLimit = -1
	} else {
		m.HoldLimit = hold
	}
	// With a document model, it reads the documents each run collects while
	// the run goes on and gives the run the organizations they name as leads.
	j := review.OpenJournal(journal, g.Repo)
	if cfg.AI.DocumentModelEnabled() && j != nil && g.Repo != nil {
		model, modelID, timeout, err := ai.DocumentModel(cfg.AI.Documents)
		if err != nil {
			c.Close()
			return nil, nil, err
		}

		dg := g
		dg.WithholdDocumentText = false
		m.Companions = append(m.Companions, &ai.DocumentCompanion{Graph: dg, Store: g.Repo,
			Journal: j, Model: model, ModelID: modelID, ModelTimeout: timeout,
			Pages: ai.DocumentPages(cfg.AI.Documents, model), ChunkChars: cfg.AI.Documents.ChunkChars,
			MaxLeads: cfg.AI.Documents.MaxLeads, Hold: hold,
			MaxChunks: cfg.AI.Documents.MaxChunks, DocumentTimeout: cfg.AI.Documents.DocumentTimeoutDuration()})
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = m.Resume(ctx)
	}()

	op := &Operator{Collect: m, Graph: g, Journal: j, RequireConfirmation: opts.RequireConfirmation,
		AnnounceDecisions: cfg.AnnounceAIDecisions(os.LookupEnv)}
	if cfg.AI != nil {
		op.Documents, op.ShareDocuments = cfg.AI.Documents, cfg.AI.DocumentsShared()
	}
	stopWatches := func() {}
	if opts.WatchFile != "" {
		runner := ai.ToolRunner{Graph: g, Catalog: oamrepo.Catalog{}, Limits: graph.DefaultLimits()}
		op.Watches = &collect.Watches{Manager: m, Path: opts.WatchFile, Topic: coord.Open(g.Repo, "watches"),
			Leases: m.Leases,
			Summarize: func(ctx context.Context, run collect.Run) string {
				if s, ok := foundSince(ctx, runner, run).(string); ok {
					return s
				}

				return ""
			}}
		ctx, cancel := context.WithCancel(context.Background())
		go op.Watches.Run(ctx)
		stopWatches = cancel
	}
	if opts.PublicURL != "" {
		op.Approvals = &ApprovalLinks{BaseURL: opts.PublicURL}
	}
	// credentials go to the store in the database when this server has the
	// secrets key, so every engine on the database uses them
	op.Secrets = secrets.Open(g.Repo, key)
	if path, err := collect.DataSourcesPath(cfg); err == nil {
		op.DataSources = path
	}
	if opts.PublicURL != "" && (op.DataSources != "" || op.Secrets != nil) {
		op.KeyLinks = &KeyLinks{BaseURL: opts.PublicURL, Path: op.DataSources, Store: op.Secrets}
	}

	return op, func() { stopWatches(); m.Close(); c.Close() }, nil
}
