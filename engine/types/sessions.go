// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"log/slog"
	"net"
	"sync"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/pubsub"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	"github.com/owasp-amass/asset-db/cache"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
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
	Queue() SessionQueue
	CIDRanger() cidranger.Ranger
	TmpDir() string
	Stats() *SessionStats
	Done() bool
	Kill()
}

type SessionQueue interface {
	Has(e *dbt.Entity) bool
	Append(e *dbt.Entity) error
	Next(atype oam.AssetType, num int) ([]*dbt.Entity, error)
	Processed(e *dbt.Entity) error
	Delete(e *dbt.Entity) error
	Close() error
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
	GetSessions() []Session
	Shutdown()
}

type AmassRangerEntry interface {
	Network() net.IPNet
	AutonomousSystem() int
	Source() *Source
}
