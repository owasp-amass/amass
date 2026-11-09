// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Command amass-ai-classifier serves the independent, local classifier.
// If no trained model is mounted, it routes observed OAM evidence to review or escalation without claiming ownership.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/classify"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "amass-ai-classifier:", err)
		os.Exit(1)
	}
}

func run() error {
	path := strings.TrimSpace(os.Getenv("AMASS_AI_CLASSIFIER_MODEL"))
	var model *classify.LinearModel
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("read classifier model: %w", err)
			}

			// A missing model path is not considered a healthy trained model.
			fmt.Fprintln(os.Stderr, "classifier: trained model missing; enabling default OAM evidence triage")
		} else {
			m, err := classify.Load(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("invalid classifier artifact: %w", err)
			}
			if m.FeatureVersion != ai.OrganizationFeatureVersion || m.Task != ai.OrganizationClassificationTask {
				return errors.New("classifier model has incompatible task or feature version")
			}

			model = m
			fmt.Fprintln(os.Stderr, "classifier: validated model artifact", m.ModelID)
		}
	}
	if model == nil {
		fmt.Fprintln(os.Stderr,
			"classifier: default OAM provenance classifier active; review/escalation only, no ownership conclusions")
	}

	addr := os.Getenv("AMASS_AI_CLASSIFIER_LISTEN")
	if addr == "" {
		addr = "0.0.0.0:8092"
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           classify.HTTPService{Model: model}.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    8192,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = srv.Shutdown(shutdown)
	}()
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return err
}
