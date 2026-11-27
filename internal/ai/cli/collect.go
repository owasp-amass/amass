// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/config"
	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/collect"
)

type collectionResponse struct {
	Status       string            `json:"status"`
	Plan         ai.CollectionPlan `json:"plan"`
	SessionToken string            `json:"session_token,omitempty"`
}

// collectTarget is deliberately separate from model tools. Without the exact
// confirmation ID of the reviewed plan, neither an engine session nor an
// Internet request can be created. The ID is not a secret (see CollectionPlan). This phase starts one passive session and returns its token;
// session monitoring and automatic query resumption are future integrations.
func collectTarget(ctx context.Context, cfg *config.Config, plan ai.CollectionPlan, approved string, execute bool, out io.Writer) error {
	response := collectionResponse{Status: plan.Status, Plan: plan}
	if !execute {
		return json.NewEncoder(out).Encode(response)
	}
	if plan.Status != "approval_required" || plan.ID == "" {
		return fmt.Errorf("unsupported collection target: %s", plan.Reason)
	}
	if approved == "" || approved != plan.ID {
		return errors.New("collection requires -approve-collection matching the exact plan id")
	}

	asset, err := collect.Configure(cfg, plan)
	if err != nil {
		return err
	}

	endpoint := collect.EngineURL(cfg)
	c, err := client.NewClient(endpoint)
	if err != nil {
		return err
	}

	defer c.Close()
	token, err := c.CreateSession(ctx, cfg)
	if err != nil {
		return fmt.Errorf("create approved collection session: %w", err)
	}
	// A seed failure must not leave an unapproved idle session behind.
	if _, err := c.CreateAsset(ctx, token, asset); err != nil {
		_ = c.TerminateSession(context.Background(), token)
		return fmt.Errorf("seed approved collection session: %w", err)
	}

	response.Status = "started"
	response.SessionToken = token.String()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(response)
}
