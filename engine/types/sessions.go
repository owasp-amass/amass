// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/pubsub"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/yl2chen/cidranger"
)

type Session interface {
	ID() uuid.UUID
	Ctx() context.Context
	Log() *slog.Logger
	PubSub() *pubsub.Logger
	Config() *config.Config
	Scope() Scope
	StartTime() time.Time
	DB() repository.Repository
	Backlog() Backlog
	CIDRanger() cidranger.Ranger
	TmpDir() string
	Stats() *SessionStats
	Done() bool
	Kill()
}

type Association struct {
	Submission  *dbt.Entity
	ScopeChange bool
	BestMatch   *dbt.Entity
	Evidence    []*dbt.Entity
	Rationale   string
	Confidence  int
}

type Scope interface {
	// Methods for modifying and querying the scope
	Add(a oam.Asset) bool
	IsAssetInScope(a oam.Asset, conf int) (oam.Asset, int)
	AddBlacklist(name string)
	IsBlacklisted(a oam.Asset) bool

	// Methods that support detecting association
	IsAssociated(req *Association) ([]*Association, error)
	AssetsWithAssociation(asset *dbt.Entity) []*dbt.Entity

	// Methods for adding and getting FQDNs
	Domains() []string
	FQDNs() []*oamdns.FQDN
	AddDomain(d string) bool

	// Methods for adding and getting IP addresses
	Addresses() []string
	AddAddress(addr string) bool
	IPAddresses() []*oamnet.IPAddress

	// Methods for adding and getting Netblocks
	CIDRs() []string
	AddCIDR(cidr string) bool
	Netblocks() []*oamnet.Netblock

	// Methods for adding and getting autonomous systems
	ASNs() []int
	AddASN(asn int) bool
	AutonomousSystems() []*oamnet.AutonomousSystem

	// Methods for adding and getting Organizations
	AddOrgByName(o string) bool
	Organizations() []*oamorg.Organization

	// Methods for adding and getting Locations
	Locations() []*oamcon.Location
	AddLocation(loc *oamcon.Location) bool
}

// Backlog is the durable, per-session work backlog with claim/lease semantics.
// Items are:
//   - Enqueued (queued)
//   - Claimed (leased/in-flight)
//   - Acked (done) or Released (returned to queued)
type Backlog interface {
	Has(e *dbt.Entity) bool

	Enqueue(e *dbt.Entity) error
	EnqueueDone(e *dbt.Entity) error

	// ClaimNext leases up to num entities of this asset type.
	// Claimed items will not be returned again until Ack/Release or lease expiry.
	ClaimNext(atype oam.AssetType, num int) ([]*dbt.Entity, error)

	// Ack marks completion (done). Call on actual completion (e.g. pipeline finished).
	Ack(e *dbt.Entity, enforceOwner bool) error

	// Release returns a leased item back to queued (e.g. backpressure/admission failure).
	Release(e *dbt.Entity, atype oam.AssetType, enforceOwner bool) error

	Counts(atype oam.AssetType) (queued, leased, done int64, err error)

	Delete(e *dbt.Entity) error
	Close() error

	// Optional knobs:
	SetOwner(owner string)
	SetLeaseTTL(ttl time.Duration)
}

type SessionStats struct {
	sync.RWMutex
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
