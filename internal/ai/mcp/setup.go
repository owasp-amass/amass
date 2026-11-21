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
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
)

// OperatorOptions configures NewOperator.
type OperatorOptions struct {
	// Dir and ConfigFile load a fresh configuration for each enumeration.
	Dir, ConfigFile string
	// RunJournal records enumeration runs (JSON lines); empty keeps them in
	// memory only.
	RunJournal string
	// WatchFile keeps scheduled enumerations; empty disables watches.
	WatchFile string
	// PublicURL is how a user's browser reaches the HTTP server, for
	// data source key links; empty disables them.
	PublicURL           string
	RequireConfirmation bool
	// MaxRunning, IdleTimeout and MaxDuration bound enumerations; zero
	// keeps the collect package's defaults.
	MaxRunning  int
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
		MaxRunning:  opts.MaxRunning,
		IdleTimeout: opts.IdleTimeout,
		MaxDuration: opts.MaxDuration,
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = m.Resume(ctx)
	}()

	op := &Operator{Collect: m, Graph: g, Journal: journal, RequireConfirmation: opts.RequireConfirmation,
		AnnounceDecisions: cfg.AnnounceAIDecisions(os.LookupEnv)}
	stopWatches := func() {}
	if opts.WatchFile != "" {
		runner := ai.ToolRunner{Graph: g, Catalog: oamrepo.Catalog{}, Limits: graph.DefaultLimits()}
		op.Watches = &collect.Watches{Manager: m, Path: opts.WatchFile,
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
	if path, err := collect.DataSourcesPath(cfg); err == nil {
		op.DataSources = path
		if opts.PublicURL != "" {
			op.KeyLinks = &KeyLinks{BaseURL: opts.PublicURL, Path: path}
		}
	}

	return op, func() { stopWatches(); m.Close(); c.Close() }, nil
}
