// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type horaddr struct {
	name   string
	plugin *horizPlugin
}

func (h *horaddr) Name() string {
	return h.name
}

func (h *horaddr) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to cast the IPAddress asset")
	}

	ptr, err := h.lookupPTRRecordName(e.Session, e.Entity)
	if err != nil {
		return nil
	}

	fqdn, err := h.lookupPTRRecordData(e.Session, ptr)
	if err != nil {
		return nil
	}

	h.process(e, ip, fqdn)
	return nil
}

func (h *horaddr) lookupPTRRecordName(sess et.Session, ip *dbt.Entity) (*dbt.Entity, error) {
	since, err := support.TTLStartTime(sess.Config(), string(oam.IPAddress), string(oam.FQDN), h.plugin.name)
	if err != nil || since.IsZero() {
		return nil, errors.New("IPAddress -> FQDN transformation not supported")
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, ip, since, "ptr_record")
	if err != nil || len(edges) == 0 {
		return nil, fmt.Errorf("no PTR records found for %s", ip.Asset.Key())
	}

	ptr, err := sess.DB().FindEntityById(ctx, edges[0].ToEntity.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire the entity with ID: %s", edges[0].ToEntity.ID)
	}

	return ptr, nil
}

func (h *horaddr) lookupPTRRecordData(sess et.Session, ptr *dbt.Entity) (*dbt.Entity, error) {
	since, err := support.TTLStartTime(sess.Config(), string(oam.FQDN), string(oam.FQDN), h.plugin.name)
	if err != nil || since.IsZero() {
		return nil, errors.New("FQDN -> FQDN transformation not supported")
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, ptr, since, "dns_record")
	if err != nil || len(edges) == 0 {
		return nil, fmt.Errorf("no PTR data found for %s", ptr.Asset.Key())
	}

	for _, edge := range edges {
		if rel, ok := edge.Relation.(*oamdns.BasicDNSRelation); !ok || rel.Header.RRType != 12 {
			continue
		}

		to, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID)
		if err != nil {
			continue
		}

		if _, valid := to.Asset.(*oamdns.FQDN); valid {
			return to, nil
		}
	}

	return nil, errors.New("failed to obtain the FQDN from the PTR data")
}

func (h *horaddr) process(e *et.Event, ip *oamnet.IPAddress, fqdn *dbt.Entity) {
	// The neighborhood sweep is informed by infrastructure ownership: when the IP
	// sits in a netblock the organization owns (confirmed by the scored
	// infrastructure correlation and in scope), the range is the org's, so the
	// sweep runs — but bounded by that netblock's sweep budget so a large owned
	// network is not probed wholesale (see performSweep). Otherwise the sweep
	// runs only when the IP's PTR name is in scope — a name-confirmed IP
	// justifies a modest probe of its immediate neighbors, but adjacency in an
	// unowned (often shared/cloud) range is not evidence of ownership, so it
	// stays narrow.
	cidr, owned := h.inOwnedNetblock(e.Session, ip)
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn.Asset, 0); conf > 0 || owned {
		h.performSweep(e, ip, cidr, owned)
	}
}

// inOwnedNetblock reports whether the IP falls within a netblock already in
// scope — i.e. one the organization owns, per the scored infrastructure
// correlation (or an operator-provided netblock) — and returns that netblock's
// CIDR so the sweep can be charged against its budget.
func (h *horaddr) inOwnedNetblock(sess et.Session, ip *oamnet.IPAddress) (string, bool) {
	for _, nb := range sess.Scope().Netblocks() {
		if nb != nil && nb.CIDR.Contains(ip.Address) {
			return nb.CIDR.String(), true
		}
	}
	return "", false
}

func (h *horaddr) performSweep(e *et.Event, ip *oamnet.IPAddress, cidr string, owned bool) {
	size := 32
	if e.Session.Config().Active {
		size = 64
	}

	// In an owned netblock the sweep is governed by that netblock's sweep budget,
	// so a large owned network is not swept wholesale on the strength of
	// ownership alone: the sweep probes only what the budget grants, records the
	// addresses it spent, and those that prove to host a real asset refund the
	// budget on the attribution drain (support.RecheckSweepBudgets). A netblock
	// whose budget is exhausted (dead space) is left alone.
	if owned {
		budget := support.SweepBudgetFor(e.Session.ID().String())
		granted := budget.TrySpend(cidr, size)
		if granted <= 0 {
			return
		}
		support.IPAddressSweep(e, ip, h.plugin.source, granted, func(ev *et.Event, a *oamnet.IPAddress, src *et.Source) {
			budget.RecordSwept(cidr, a.Address.String())
			h.plugin.submitIPAddress(ev, a, src)
		})
		return
	}

	// A name-confirmed IP in an un-owned (often shared/cloud) range justifies
	// only a modest, fixed probe of its immediate neighbors.
	support.IPAddressSweep(e, ip, h.plugin.source, size, h.plugin.submitIPAddress)
}
