// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/netmap"
	"github.com/caffix/resolve"
	"github.com/caffix/service"
)

func setupMockScriptEnv(script string) (service.Service, systems.System) {
	sys := newMockSystem(config.NewConfig())

	if s := NewScript(script, sys); s != nil {
		if err := sys.AddAndStart(s); err == nil {
			return s, sys
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

	ss.Pool.SetLogger(cfg.Log)
	_ = ss.Pool.AddResolvers(20, "8.8.8.8")
	ss.Trusted.SetLogger(cfg.Log)
	_ = ss.Trusted.AddResolvers(20, "8.8.8.8")
	return ss
}
