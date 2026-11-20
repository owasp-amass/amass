// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

// bgpview enumerates BGP routing data from BGPView (api.bgpview.io), a free,
// key-less JSON API. It adds two pivots that corroborate the engine's existing
// BGP sources rather than replacing them:
//   - AutonomousSystem -> every prefix the AS announces (alongside GitHub-IPVerse),
//     so the full announced address space is recorded, not only the prefixes that
//     contain an already-seen IP.
//   - IPAddress -> its covering prefix and announcing AS (alongside BGP.Tools).
//
// Each record is written to the shared AutonomousSystem/Netblock assets and the
// "announces" edge with BGPView's own SourceProperty, so agreement across
// sources is visible in the evidence.
type bgpview struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewBGPView() et.Plugin {
	return &bgpview{
		name:   "BGPView",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{Name: "BGPView", Confidence: 90},
	}
}

func (b *bgpview) Name() string { return b.name }

func (b *bgpview) Start(r et.Registry) error {
	b.log = r.Log().WithGroup("plugin").With("name", b.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       b,
		Name:         b.name + "-ASN-Handler",
		Position:     31,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Netblock)},
		EventType:    oam.AutonomousSystem,
		Callback:     b.checkASN,
	}); err != nil {
		return err
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       b,
		Name:         b.name + "-IP-Handler",
		Position:     4,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Netblock), string(oam.AutonomousSystem)},
		EventType:    oam.IPAddress,
		Callback:     b.checkIP,
	}); err != nil {
		return err
	}

	b.log.Info("Plugin started")
	return nil
}

func (b *bgpview) Stop() { b.log.Info("Plugin stopped") }

// checkASN records every prefix BGPView reports the AS announcing.
func (b *bgpview) checkASN(e *et.Event) error {
	as, ok := e.Entity.Asset.(*oamnet.AutonomousSystem)
	if !ok {
		return errors.New("failed to extract the AutonomousSystem asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.AutonomousSystem), string(oam.Netblock), b.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, b.source, since) {
		return nil
	}

	body, ok := b.fetch(e.Session, fmt.Sprintf("https://api.bgpview.io/asn/%d/prefixes", as.Number))
	if !ok {
		return nil
	}
	var res struct {
		Status string `json:"status"`
		Data   struct {
			IPv4 []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv4_prefixes"`
			IPv6 []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil || res.Status != "ok" {
		return nil
	}

	support.MarkAssetMonitored(e.Session, e.Entity, b.source)
	var n int
	for _, p := range res.Data.IPv4 {
		if b.storeAnnounced(e, e.Entity, as.Number, p.Prefix) {
			n++
		}
	}
	for _, p := range res.Data.IPv6 {
		if b.storeAnnounced(e, e.Entity, as.Number, p.Prefix) {
			n++
		}
	}
	if n > 0 {
		e.Session.Log().Info("AS prefixes enumerated", "asn", as.Number, "prefixes", n,
			slog.Group("plugin", "name", b.name, "handler", b.name+"-ASN-Handler"))
	}
	return nil
}

// checkIP records the covering prefix and announcing AS for an address.
func (b *bgpview) checkIP(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.IPAddress), string(oam.Netblock), b.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, b.source, since) {
		return nil
	}

	body, ok := b.fetch(e.Session, "https://api.bgpview.io/ip/"+ip.Address.String())
	if !ok {
		return nil
	}
	var res struct {
		Status string `json:"status"`
		Data   struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
				ASN    struct {
					ASN int `json:"asn"`
				} `json:"asn"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil || res.Status != "ok" {
		return nil
	}

	support.MarkAssetMonitored(e.Session, e.Entity, b.source)
	// Prefer the most specific (longest-mask) covering prefix.
	best, bestBits, bestASN := "", -1, 0
	for _, p := range res.Data.Prefixes {
		pfx, err := netip.ParsePrefix(p.Prefix)
		if err != nil || !pfx.Contains(ip.Address) {
			continue
		}
		if pfx.Bits() > bestBits {
			best, bestBits, bestASN = p.Prefix, pfx.Bits(), p.ASN.ASN
		}
	}
	if best == "" || bestASN == 0 {
		return nil
	}

	nb := b.storeNetblock(e, best)
	if nb == nil {
		return nil
	}
	b.edge(e, nb, e.Entity, "contains")
	if as := b.storeAutnum(e, bestASN); as != nil {
		b.edge(e, as, nb, "announces")
		b.dispatch(e, as, "AS"+as.Asset.Key())
	}
	b.dispatch(e, nb, nb.Asset.Key())
	return nil
}

// storeAnnounced records one announced prefix as a Netblock, links the AS to it
// with an announces edge, primes the session ranger, and dispatches it.
func (b *bgpview) storeAnnounced(e *et.Event, as *dbt.Entity, asn int, prefix string) bool {
	nb := b.storeNetblock(e, prefix)
	if nb == nil {
		return false
	}
	b.edge(e, as, nb, "announces")
	_ = support.AddNetblock(e.Session, prefix, asn, b.source)
	b.dispatch(e, nb, nb.Asset.Key())
	return true
}

func (b *bgpview) storeNetblock(e *et.Event, prefix string) *dbt.Entity {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil
	}
	ntype := "IPv4"
	if pfx.Addr().Is6() {
		ntype = "IPv6"
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	nb, err := e.Session.DB().CreateAsset(ctx, &oamnet.Netblock{CIDR: pfx, Type: ntype})
	if err != nil || nb == nil {
		return nil
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, nb, &general.SourceProperty{
		Source:     b.source.Name,
		Confidence: b.source.Confidence,
	})
	return nb
}

func (b *bgpview) storeAutnum(e *et.Event, asn int) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	as, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: asn})
	if err != nil || as == nil {
		return nil
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, as, &general.SourceProperty{
		Source:     b.source.Name,
		Confidence: b.source.Confidence,
	})
	return as
}

func (b *bgpview) edge(e *et.Event, from, to *dbt.Entity, label string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 20*time.Second)
	defer cancel()

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: label},
		FromEntity: from,
		ToEntity:   to,
	})
	if err != nil || edge == nil {
		return
	}
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     b.source.Name,
		Confidence: b.source.Confidence,
	})
}

func (b *bgpview) dispatch(e *et.Event, entity *dbt.Entity, name string) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    name,
		Entity:  entity,
		Session: e.Session,
	})
}

func (b *bgpview) fetch(sess et.Session, url string) (string, bool) {
	if err := support.WaitLimit(sess.Ctx(), b.rlimit); err != nil {
		return "", false
	}

	sess.NetSem().Acquire()
	defer sess.NetSem().Release()

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, sess.Clients().General, &amasshttp.Request{URL: url})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK || resp.Body == "" {
		return "", false
	}
	return resp.Body, true
}
