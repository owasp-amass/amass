// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"net/netip"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdb "github.com/owasp-amass/amass/v5/internal/db"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// FingerprintCarrierInScope reports whether the fingerprint Identifier in the
// event is carried by a service on a host in the session scope: Identifier
// <--fingerprint-- Service <--port-- FQDN/IPAddress, any of which in scope. The
// reverse-search collectors use it so they act only on the organization's own
// fingerprints, not every Identifier in the shared database.
func FingerprintCarrierInScope(e *et.Event) bool {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	fpEdges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, time.Time{}, "fingerprint")
	if err != nil || len(fpEdges) == 0 {
		return false
	}

	svcs := amassdb.EdgeEnds(ctx, e.Session.DB(), fpEdges, true)
	for _, fe := range fpEdges {
		svc, ok := svcs[fe.FromEntity.ID]
		if !ok {
			continue
		}

		portEdges, err := e.Session.DB().IncomingEdges(ctx, svc, time.Time{}, "port")
		if err != nil {
			continue
		}

		hosts := amassdb.EdgeEnds(ctx, e.Session.DB(), portEdges, true)
		for _, pe := range portEdges {
			if host, ok := hosts[pe.FromEntity.ID]; ok {
				if _, conf := e.Session.Scope().IsAssetInScope(host.Asset, 0); conf > 0 {
					return true
				}
			}
		}
	}

	return false
}

// StoreOriginIP records a reverse-search hit as an IPAddress with src
// provenance and enqueues it for Amass's own service discovery to probe. No
// Service or fingerprint edge is synthesized: a third-party report becomes an
// Amass observation only when a probe confirms it (ai-design-principles.md,
// principle 10). It reports whether the address was stored.
func StoreOriginIP(e *et.Event, src *et.Source, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	ipa := &oamnet.IPAddress{Address: addr, Type: "IPv4"}
	if addr.Is6() {
		ipa.Type = "IPv6"
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 20*time.Second)
	defer cancel()

	ent, err := e.Session.DB().CreateAsset(ctx, ipa)
	if err != nil || ent == nil {
		return false
	}

	_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &oamgen.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
	_ = e.Session.Backlog().Enqueue(ent)

	return true
}
