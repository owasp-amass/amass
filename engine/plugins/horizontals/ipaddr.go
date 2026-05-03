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
	// sweep around the IP, if the PTR record resolves to a FQDN that's in scope
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn.Asset, 0); conf > 0 {
		h.performSweep(e, ip)
	}
}

func (h *horaddr) performSweep(e *et.Event, ip *oamnet.IPAddress) {
	size := 32
	if e.Session.Config().Active {
		size = 64
	}

	support.IPAddressSweep(e, ip, h.plugin.source, size, h.plugin.submitIPAddress)
}
