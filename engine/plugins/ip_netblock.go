// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/sessions"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type ipNetblock struct {
	name   string
	log    *slog.Logger
	source *et.Source
	stored *storedNetblocks
}

// storedNetblocks remembers, per session, the netblocks and autonomous
// systems this plugin has stored with their announces relation. Every
// address of a netblock shares them, so only an address's own contains
// relation is stored for it: the netblock, the AS, the announces relation
// and their sources are stored once per session, not once per address.
type storedNetblocks struct {
	sync.Mutex
	m map[storedNetblockKey]storedNetblock
}

type storedNetblockKey struct {
	session uuid.UUID
	cidr    string
	asn     int
	source  string
}

type storedNetblock struct{ nb, as *dbt.Entity }

// maxStoredNetblocks bounds the cache; it is emptied when full.
const maxStoredNetblocks = 1 << 14

func (s *storedNetblocks) get(k storedNetblockKey) (storedNetblock, bool) {
	s.Lock()
	defer s.Unlock()

	v, ok := s.m[k]
	return v, ok
}

func (s *storedNetblocks) put(k storedNetblockKey, v storedNetblock) {
	s.Lock()
	defer s.Unlock()

	if s.m == nil || len(s.m) >= maxStoredNetblocks {
		s.m = map[storedNetblockKey]storedNetblock{}
	}
	s.m[k] = v
}

func (s *storedNetblocks) forget(k storedNetblockKey) {
	s.Lock()
	defer s.Unlock()

	delete(s.m, k)
}

func NewIPNetblock() et.Plugin {
	return &ipNetblock{
		name: "IP-Netblock",
		source: &et.Source{
			Name:       "IP-Netblock",
			Confidence: 100,
		},
		stored: &storedNetblocks{},
	}
}

func (d *ipNetblock) Name() string {
	return d.name
}

func (d *ipNetblock) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	name := d.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         name,
		Position:     4,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.Netblock)},
		EventType:    oam.IPAddress,
		Callback:     d.lookup,
	}); err != nil {
		d.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *ipNetblock) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *ipNetblock) lookup(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	if reserved, cidr := amassnet.IsReservedAddress(ip.Address.String()); reserved {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil
		}

		netblock := &oamnet.Netblock{
			Type: "IPv4",
			CIDR: prefix,
		}
		if prefix.Addr().Is6() {
			netblock.Type = "IPv6"
		}

		d.reservedAS(e, netblock)
		return nil
	}

	var entry *sessions.CIDRangerEntry
	for range 120 {
		entry = support.IPNetblock(e.Session, ip.Address.String())
		if entry != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if entry == nil {
		return nil
	}

	nb, as, first := d.store(e, entry)
	if nb == nil || as == nil {
		return nil
	}

	d.process(e, e.Entity, nb, as, first)
	return nil
}

// store records that the netblock contains the event's address, storing
// the netblock, its AS and the announces relation the first time the
// session sees them. It reports whether they were new to the session.
func (d *ipNetblock) store(e *et.Event, entry *sessions.CIDRangerEntry) (*dbt.Entity, *dbt.Entity, bool) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	k := storedNetblockKey{session: e.Session.ID(), cidr: entry.Net.String(), asn: entry.ASN, source: entry.Src.Name}
	shared, known := d.stored.get(k)
	if known {
		// The cached netblock may have been removed (merged) since.
		if !d.storeContains(ctx, e, entry, shared.nb) {
			d.stored.forget(k)
			known = false
		}
	}
	if !known {
		nb, as := d.storeNetblock(ctx, e, entry)
		if nb == nil || as == nil || !d.storeContains(ctx, e, entry, nb) {
			return nil, nil, false
		}

		shared = storedNetblock{nb: nb, as: as}
		d.stored.put(k, shared)
	}

	return shared.nb, shared.as, !known
}

// storeNetblock stores the netblock and its AS, the announces relation and
// their sources.
func (d *ipNetblock) storeNetblock(ctx context.Context, e *et.Event,
	entry *sessions.CIDRangerEntry) (*dbt.Entity, *dbt.Entity) {
	prefix, err := netip.ParsePrefix(entry.Net.String())
	if err != nil {
		return nil, nil
	}

	netblock := &oamnet.Netblock{Type: "IPv4", CIDR: prefix}
	if netblock.CIDR.Addr().Is6() {
		netblock.Type = "IPv6"
	}

	nb, err := e.Session.DB().CreateAsset(ctx, netblock)
	if err != nil || nb == nil {
		return nil, nil
	}

	support.AddSource(ctx, e.Session, nb, entry.Src)
	as, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: entry.ASN})
	if err != nil || as == nil {
		return nil, nil
	}

	support.AddSource(ctx, e.Session, as, entry.Src)
	if _, err := support.Relate(ctx, e.Session, as, &general.SimpleRelation{Name: "announces"}, nb, entry.Src); err != nil {
		return nil, nil
	}
	return nb, as
}

// storeContains stores that the netblock contains the event's address.
func (d *ipNetblock) storeContains(ctx context.Context, e *et.Event, entry *sessions.CIDRangerEntry,
	nb *dbt.Entity) bool {
	if _, err := support.Relate(ctx, e.Session, nb, &general.SimpleRelation{Name: "contains"}, e.Entity, entry.Src); err != nil {
		return false
	}
	return true
}

// process logs the address's netblock and, the first time the session sees
// them, sends the netblock and its AS on as events and logs the announces
// relation.
func (d *ipNetblock) process(e *et.Event, ip, nb, as *dbt.Entity, first bool) {
	ipstr := ip.Asset.Key()
	nbname := nb.Asset.Key()

	e.Session.Log().Info("relationship discovered", "from", nbname, "relation", "contains",
		"to", ipstr, slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
	if !first {
		return
	}

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    nb.Asset.Key(),
		Entity:  nb,
		Session: e.Session,
	})

	asname := "AS" + as.Asset.Key()
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    asname,
		Entity:  as,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", asname, "relation", "announces",
		"to", nbname, slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
}

func (d *ipNetblock) reservedAS(e *et.Event, netblock *oamnet.Netblock) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	nb, err := e.Session.DB().CreateAsset(ctx, netblock)
	if err != nil || nb == nil {
		return
	}

	support.AddSource(ctx, e.Session, nb, d.source)

	asn, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: 0})
	if err != nil || asn == nil {
		return
	}

	support.AddSource(ctx, e.Session, asn, d.source)

	_, _ = support.Relate(ctx, e.Session, asn, &general.SimpleRelation{Name: "announces"}, nb, d.source)
}
