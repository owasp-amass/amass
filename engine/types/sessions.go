// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"log/slog"
	"net"
	"sync"

	"github.com/caffix/stringset"
	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine/pubsub"
	"github.com/owasp-amass/amass/v4/engine/sessions/scope"
	"github.com/owasp-amass/asset-db/cache"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/yl2chen/cidranger"
)

type Session interface {
	ID() uuid.UUID
	Log() *slog.Logger
	PubSub() *pubsub.Logger
	Config() *config.Config
	Scope() *scope.Scope
	DB() repository.Repository
	Cache() *cache.Cache
	CIDRanger() cidranger.Ranger
	TmpDir() string
	Stats() *SessionStats
	EventSet() *stringset.Set
	Done() bool
	Kill()
}

type SessionStats struct {
	sync.Mutex
	WorkItemsCompleted int `json:"workItemsCompleted"`
	WorkItemsTotal     int `json:"workItemsTotal"`
}

type SessionManager interface {
	NewSession(cfg *config.Config) (Session, error)
	AddSession(s Session) error
	CancelSession(id uuid.UUID)
	GetSession(id uuid.UUID) Session
	Shutdown()
}

type AmassRangerEntry interface {
	Network() net.IPNet
	AutonomousSystem() int
	Source() *Source
}
