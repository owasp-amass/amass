// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"io"
	"log/slog"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/registry"
)

// TestLoadAndStartPlugins ensures every registered plugin starts and registers
// its handlers without conflict. Registering two exclusive handlers at the same
// position for one EventType fails, which aborts startup and leaves the engine
// unhealthy, so this guards against that regression.
func TestLoadAndStartPlugins(t *testing.T) {
	r := registry.NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := LoadAndStartPlugins(r); err != nil {
		t.Fatalf("plugins failed to load and register cleanly: %v", err)
	}
}
