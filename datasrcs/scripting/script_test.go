// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package scripting

import (
	"context"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/netmap"
	"github.com/caffix/resolve"
)

func setupMockScriptEnv(script string) (context.Context, systems.System) {
	cfg := config.NewConfig()
	sys := newMockSystem(cfg)
	bus := eventbus.NewEventBus()

	ctx := context.WithValue(context.Background(), requests.ContextConfig, cfg)
	ctx = context.WithValue(ctx, requests.ContextEventBus, bus)

	if s := NewScript(script, sys); s != nil {
		sys.AddAndStart(s)
		return ctx, sys
	}
	return nil, nil
}

func newMockSystem(cfg *config.Config) systems.System {
	return &systems.SimpleSystem{
		Cfg:      cfg,
		Resolver: resolve.NewBaseResolver("8.8.8.8", 50, cfg.Log),
		Graph:    netmap.NewGraph(netmap.NewCayleyGraphMemory()),
		ASNCache: requests.NewASNCache(),
	}
}
