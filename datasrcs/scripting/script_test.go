// Copyright © by Jeff Foley 2021-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

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

	ctx := context.WithValue(context.Background(), requests.ContextConfig, cfg)
	ctx = context.WithValue(ctx, requests.ContextEventBus, eventbus.NewEventBus())

	if s := NewScript(script, sys); s != nil {
		if err := sys.AddAndStart(s); err == nil {
			return ctx, sys
		}
	}
	return nil, nil
}

func newMockSystem(cfg *config.Config) systems.System {
	ss := &systems.SimpleSystem{
		Cfg:      cfg,
		Pool:     resolve.NewResolvers(),
		Trusted:  resolve.NewResolvers(),
		Graph:    netmap.NewGraph(netmap.NewCayleyGraphMemory()),
		ASNCache: requests.NewASNCache(),
	}

	ss.Pool.AddLogger(cfg.Log)
	ss.Pool.AddResolvers(10, "8.8.8.8")
	ss.Trusted.AddLogger(cfg.Log)
	ss.Trusted.AddResolvers(10, "8.8.8.8")
	return ss
}
