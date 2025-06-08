// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/owasp-amass/amass/v4/engine/api/graphql/server"
	"github.com/owasp-amass/amass/v4/engine/dispatcher"
	"github.com/owasp-amass/amass/v4/engine/registry"
	"github.com/owasp-amass/amass/v4/engine/sessions"
	et "github.com/owasp-amass/amass/v4/engine/types"
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

	reg := registry.NewRegistry(l)
	if reg == nil {
		return nil, errors.New("failed to create the handler registry")
	}

	mgr := sessions.NewManager(l)
	if mgr == nil {
		return nil, errors.New("failed to create the session manager")
	}

	dis := dispatcher.NewDispatcher(l, reg, mgr)
	if dis == nil {
		mgr.Shutdown()
		return nil, errors.New("failed to create the event scheduler")
	}

	srv := server.NewServer(l, dis, mgr)
	if srv == nil {
		dis.Shutdown()
		mgr.Shutdown()
		return nil, errors.New("failed to create the API server")
	}

	ch := make(chan error, 1)
	go func(errch chan error) { errch <- srv.Start() }(ch)

	t := time.NewTimer(2 * time.Second)
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
		// If the server does not return an error within 2 seconds, we assume it started successfully
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
