// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
)

// TestEngineStartsAndServes starts the whole engine (every plugin, the
// session manager and the API server on port 4000) and checks that the API
// answers. It needs the ports free and the plugins' resources, so it runs
// only with AMASS_LIVE_ENGINE=1.
func TestEngineStartsAndServes(t *testing.T) {
	if os.Getenv("AMASS_LIVE_ENGINE") == "" {
		t.Skip("set AMASS_LIVE_ENGINE=1 to start the engine")
	}

	e, err := NewEngine(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Shutdown()

	c, err := client.NewClient("http://127.0.0.1:4000")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if !c.HealthCheck(ctx) {
		t.Fatal("the engine API did not answer its health check")
	}
	if _, err := c.ListSessions(ctx); err != nil {
		t.Errorf("listing sessions: %v", err)
	}
}
