// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/engine/api/graphql/server"
	"github.com/owasp-amass/amass/v5/engine/dispatcher"
	"github.com/owasp-amass/amass/v5/engine/plugins"
	"github.com/owasp-amass/amass/v5/engine/registry"
	"github.com/owasp-amass/amass/v5/engine/sessions"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

type Engine struct {
	Log        *slog.Logger
	Dispatcher et.Dispatcher
	Registry   et.Registry
	Manager    et.SessionManager
	Server     *server.Server
}

func NewEngine(l *slog.Logger) (*Engine, error) {
	if l == nil {
		l = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	mgr := sessions.NewManager(l)
	if mgr == nil {
		return nil, errors.New("failed to create the session manager")
	}
	reg := registry.NewRegistry(l)

	dis := dispatcher.NewDispatcher(l, reg, mgr)
	if dis == nil {
		mgr.Shutdown()
		return nil, errors.New("failed to create the event scheduler")
	}

	if err := plugins.LoadAndStartPlugins(reg); err != nil {
		return nil, err
	}

	if err := reg.BuildPipelines(); err != nil {
		return nil, err
	}

	srv := server.NewServer(l, dis, mgr)
	if srv == nil {
		dis.Shutdown()
		mgr.Shutdown()
		return nil, errors.New("failed to create the API server")
	}

	ch := make(chan error, 1)
	go func(errch chan error) { errch <- srv.Start() }(ch)

	t := time.NewTimer(3 * time.Second)
	defer t.Stop()

	select {
	case err := <-ch:
		if err != nil {
			_ = srv.Shutdown()
			dis.Shutdown()
			mgr.Shutdown()
			return nil, err
		}
	case <-t.C:
		// If the server does not return an error within 3 seconds, we assume it started successfully
	}

	return &Engine{
		Log:        l,
		Dispatcher: dis,
		Registry:   reg,
		Manager:    mgr,
		Server:     srv,
	}, nil
}

func (e *Engine) Shutdown() {
	_ = e.Server.Shutdown()
	e.Dispatcher.Shutdown()
	e.Manager.Shutdown()
}
