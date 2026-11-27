// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package routing reads the routing security records of the netblocks in
// scope: the routing registry (IRR) route objects that name each netblock's
// maintainer, and the RPKI Route Origin Authorizations (ROAs) that say which
// autonomous systems may announce it. Both come from RIPEstat with no key.
// For each operator maintainer it also asks a routing registry for every
// other route object that maintainer keeps, which finds the operator's other
// netblocks.
//
// Everything is an observation: a Netblock --irr_maintainer--> Identifier, a
// Netblock --rpki_origin--> AutonomousSystem, and the netblock's rpki_status.
// The infrastructure lens decides what they say about ownership.
package routing

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

// Property names this plugin stores.
const (
	// PropRPKIStatus is a netblock's RPKI validity for its announced origin:
	// valid, invalid or unknown (no ROA covers it).
	PropRPKIStatus = "rpki_status"
	// PropIRRRoutes is how many route objects a maintainer keeps; only a
	// maintainer keeping at most max_routes has its routes stored, each as a
	// Netblock --irr_maintainer--> the maintainer Identifier and
	// Netblock --irr_origin--> the route object's origin AS.
	PropIRRRoutes = "irr_routes"
)

const (
	// maxOrigins bounds the announced origins checked per netblock.
	maxOrigins = 3
	// maintainerTTL is how long one maintainer's route objects are not asked
	// for again.
	maintainerTTL = 24 * time.Hour
	// whoisReadLimit bounds a routing registry answer.
	whoisReadLimit = 4 << 20
)

type routingRecords struct {
	name    string
	log     *slog.Logger
	source  *et.Source
	rlimit  *rate.Limiter
	catalog semantics.RoutingRegistries

	mu    sync.Mutex
	asked map[string]time.Time
}

func NewRoutingRecords() et.Plugin {
	return &routingRecords{
		name:   "RPKI-IRR",
		source: &et.Source{Name: "RPKI-IRR", Confidence: 90},
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
		asked:  map[string]time.Time{},
	}
}

func (r *routingRecords) Name() string { return r.name }

func (r *routingRecords) Start(reg et.Registry) error {
	r.log = reg.Log().WithGroup("plugin").With("name", r.name)
	r.catalog = semantics.RoutingRegistryCatalog()

	if err := reg.RegisterHandler(&et.Handler{
		Plugin:       r,
		Name:         r.name + "-Handler",
		Position:     30,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Identifier), string(oam.AutonomousSystem), string(oam.Netblock)},
		EventType:    oam.Netblock,
		Callback:     r.check,
	}); err != nil {
		return err
	}

	r.log.Info("Plugin started")
	return nil
}

func (r *routingRecords) Stop() { r.log.Info("Plugin stopped") }

func (r *routingRecords) check(e *et.Event) error {
	nb, ok := e.Entity.Asset.(*oamnet.Netblock)
	if !ok || !nb.CIDR.IsValid() {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Netblock), string(oam.Identifier), r.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, r.source, since) {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, r.source)

	prefix := nb.CIDR.Masked()
	if objs, err := r.statWhois(e, prefix); err == nil {
		for _, m := range r.maintainers(objs, prefix) {
			id := r.storeMaintainer(e, e.Entity, m)
			if id != nil {
				r.expand(e, id, m)
			}
		}
	}
	r.rpki(e, e.Entity, prefix)
	return nil
}

// maintainer is an operator's handle in one routing registry.
type maintainer struct {
	source, handle string
}

func (m maintainer) id() string { return m.source + ":" + m.handle }

// maintainers returns the operator maintainers of the route objects for the
// prefix itself or more specific prefixes within it; a covering route object
// is a provider's aggregate, and a registry's own maintainers name no
// operator.
func (r *routingRecords) maintainers(objs []routeObject, prefix netip.Prefix) []maintainer {
	seen := map[maintainer]bool{}
	var out []maintainer
	for _, o := range objs {
		if o.prefix.Bits() < prefix.Bits() || !prefix.Contains(o.prefix.Addr()) {
			continue
		}
		for _, h := range o.maintainers {
			m := maintainer{source: o.source, handle: h}
			if r.catalog.RegistryMaintainer(h) || seen[m] {
				continue
			}
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// statGet fetches one RIPEstat data call.
func (r *routingRecords) statGet(e *et.Event, call string, params url.Values) ([]byte, error) {
	params.Set("sourceapp", r.catalog.SourceApp)
	u := fmt.Sprintf("%s/%s/data.json?%s", strings.TrimSuffix(r.catalog.StatAPI, "/"), call, params.Encode())

	return support.FetchBody(e, u, r.rlimit, 0)
}

func (r *routingRecords) statWhois(e *et.Event, prefix netip.Prefix) ([]routeObject, error) {
	data, err := r.statGet(e, "whois", url.Values{"resource": {prefix.String()}})
	if err != nil {
		return nil, err
	}
	return parseStatWhois(data)
}

// storeMaintainer records the maintainer as an Identifier linked from the
// netblock.
func (r *routingRecords) storeMaintainer(e *et.Event, nbent *dbt.Entity, m maintainer) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	id, err := e.Session.DB().CreateAsset(ctx, &general.Identifier{
		UniqueID: general.IRRMaintainer + ":" + m.id(), ID: m.id(), Type: general.IRRMaintainer,
	})
	if err != nil || id == nil {
		return nil
	}
	support.AddSource(ctx, e.Session, id, r.source)
	support.Link(ctx, e.Session, nbent, "irr_maintainer", id, r.source)
	return id
}

// expand asks the routing registry for every route object the maintainer
// keeps, once a day. It records how many there are on the maintainer and,
// unless the maintainer keeps more than max_routes (an ISP, host or registry
// keeping objects for many customers), links each route's netblock to it and
// to the route's origin AS.
func (r *routingRecords) expand(e *et.Event, id *dbt.Entity, m maintainer) {
	r.mu.Lock()
	if t, ok := r.asked[m.id()]; ok && time.Since(t) < maintainerTTL {
		r.mu.Unlock()
		return
	}
	r.asked[m.id()] = time.Now()
	r.mu.Unlock()

	text, err := r.whois(e.Session.Ctx(), fmt.Sprintf("-s %s -i mnt-by %s", m.source, m.handle))
	if err != nil {
		e.Session.Log().Debug("routing registry query failed", "maintainer", m.id(), "error", err,
			slog.Group("plugin", "name", r.name, "handler", r.name+"-Handler"))
		return
	}
	var routes []routeObject
	for _, o := range parseRPSL(text) {
		if o.source == m.source {
			routes = append(routes, o)
		}
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()
	support.AddProperty(ctx, e.Session, id, PropIRRRoutes, strconv.Itoa(len(routes)))
	if len(routes) > r.catalog.MaxRoutes {
		return
	}

	for _, o := range routes {
		kind := "IPv4"
		if o.prefix.Addr().Is6() {
			kind = "IPv6"
		}
		nbent, err := e.Session.DB().CreateAsset(ctx, &oamnet.Netblock{CIDR: o.prefix, Type: kind})
		if err != nil || nbent == nil {
			continue
		}
		support.AddSource(ctx, e.Session, nbent, r.source)
		support.Link(ctx, e.Session, nbent, "irr_maintainer", id, r.source)
		if o.origin > 0 {
			support.LinkAsset(ctx, e.Session, nbent, "irr_origin", &oamnet.AutonomousSystem{Number: o.origin},
				r.source)
		}
	}
	e.Session.Log().Info("routing registry maintainer read", "maintainer", m.id(), "routes", len(routes),
		slog.Group("plugin", "name", r.name, "handler", r.name+"-Handler"))
}

// whois sends one query to the routing registry whois server.
func (r *routingRecords) whois(ctx context.Context, query string) (string, error) {
	_ = support.WaitLimit(ctx, r.rlimit)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	return amassnet.WhoisQuery(ctx, r.catalog.IRRWhois, query+"\r\n", 10*time.Second, whoisReadLimit)
}

// rpki checks the netblock against RPKI for each AS that announces it, and
// records its validity and every AS a valid ROA authorizes to announce it.
func (r *routingRecords) rpki(e *et.Event, nbent *dbt.Entity, prefix netip.Prefix) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 2*time.Minute)
	defer cancel()

	edges, err := e.Session.DB().IncomingEdges(ctx, nbent, time.Time{}, "announces")
	if err != nil || len(edges) == 0 {
		return
	}

	status := ""
	authorized := map[int]bool{}
	for i, edge := range edges {
		if i >= maxOrigins {
			break
		}
		asent, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID)
		if err != nil || asent == nil {
			continue
		}
		as, ok := asent.Asset.(*oamnet.AutonomousSystem)
		if !ok {
			continue
		}

		data, err := r.statGet(e, "rpki-validation", url.Values{"resource": {fmt.Sprintf("AS%d", as.Number)},
			"prefix": {prefix.String()}})
		if err != nil {
			continue
		}
		s, roas, err := parseRPKIValidation(data)
		if err != nil {
			continue
		}
		// valid for any announced origin wins; otherwise the first answer
		if status == "" || s == "valid" {
			status = s
		}
		for _, ro := range roas {
			if ro.validity == "valid" && ro.covers(prefix) {
				authorized[ro.origin] = true
			}
		}
	}

	if status != "" {
		support.AddProperty(ctx, e.Session, nbent, PropRPKIStatus, status)
	}
	for n := range authorized {
		asent, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: n})
		if err != nil || asent == nil {
			continue
		}
		support.AddSource(ctx, e.Session, asent, r.source)
		support.Link(ctx, e.Session, nbent, "rpki_origin", asent, r.source)
	}
}
