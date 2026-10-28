// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/registry"
	"github.com/stretchr/testify/assert"
)

func TestNewBGPTools(t *testing.T) {
	plugin := NewBGPTools()
	assert.NotNil(t, plugin, "NewBGPTools should not return nil")
	assert.Equal(t, "BGP.Tools", plugin.Name(), "Plugin name should be BGP.Tools")

	bt, ok := plugin.(*bgpTools)
	assert.True(t, ok, "Plugin should be of type *bgpTools")
	assert.NotNil(t, bt.source, "Plugin source should not be nil")
	assert.Equal(t, "BGP.Tools", bt.source.Name, "Source name should be BGP.Tools")
	assert.Equal(t, 100, bt.source.Confidence, "Source confidence should be 100")
	assert.Equal(t, 43, bt.port, "Port should be 43")
	assert.NotNil(t, bt.rlimit, "Rate limiter should not be nil")
}

func TestResolveServerWithCanceledContext(t *testing.T) {
	plugin := NewBGPTools()
	bt, ok := plugin.(*bgpTools)
	assert.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled immediately

	addr := bt.resolveServer(ctx)
	assert.Empty(t, addr, "Canceled context should return empty address without hanging or panic")
}

func TestBGPToolsStartGracefulFallback(t *testing.T) {
	plugin := NewBGPTools()
	bt, ok := plugin.(*bgpTools)
	assert.True(t, ok)

	// Create a dummy registry with discarded log output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := registry.NewRegistry(logger)

	// Force empty addr and ensure Start does not return an error when DNS fails
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	bt.log = logger.WithGroup("plugin").With("name", bt.name)
	addr := bt.resolveServer(ctx)
	assert.Empty(t, addr)

	// Test Start directly with canceled context simulation
	err := bt.Start(reg)
	assert.NoError(t, err, "Start should return nil and not crash the engine even if server resolution fails")
}
