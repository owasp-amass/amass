// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// netblock is the RDAP query handler for a netblock: it turns the netblock
// into the IPNetRecord its regional registry serves.
type netblock struct {
	name   string
	plugin *rdapPlugin
}

func (nb *netblock) Name() string {
	return nb.name
}

func (nb *netblock) check(e *et.Event) error {
	n, ok := e.Entity.Asset.(*network.Netblock)
	if !ok {
		return errors.New("failed to cast the Netblock asset")
	}

	return nb.plugin.checkRegistration(e, nb.name, oam.IPNetRecord, dbt.ContentFilters{"cidr": n.CIDR.String()},
		func() (*dbt.Entity, any) { return nb.query(e, e.Entity) })
}

func (nb *netblock) query(e *et.Event, asset *dbt.Entity) (*dbt.Entity, any) {
	_ = support.WaitLimit(e.Session.Ctx(), nb.plugin.rlimit)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Minute)
	defer cancel()

	n := asset.Asset.(*network.Netblock)
	_, ipnet, err := net.ParseCIDR(n.CIDR.String())
	if err != nil {
		return nil, nil
	}
	req := rdap.NewIPNetRequest(ipnet).WithContext(ctx)

	resp, err := nb.plugin.client.Do(req)
	if err != nil {
		return nil, nil
	}

	record, ok := resp.Object.(*rdap.IPNetwork)
	if !ok || record == nil {
		return nil, nil
	}
	return nb.store(e, record, asset), record
}

func (nb *netblock) store(e *et.Event, resp *rdap.IPNetwork, asset *dbt.Entity) *dbt.Entity {
	n := asset.Asset.(*network.Netblock)
	// The addresses come from the RDAP server: a missing or malformed one
	// leaves the record unstored rather than panicking the handler.
	start, err := netip.ParseAddr(resp.StartAddress)
	if err != nil {
		return nil
	}
	end, err := netip.ParseAddr(resp.EndAddress)
	if err != nil {
		return nil
	}

	ipnetrec := &oamreg.IPNetRecord{
		CIDR:         n.CIDR,
		Handle:       resp.Handle,
		StartAddress: start,
		EndAddress:   end,
		Type:         n.Type,
		Name:         resp.Name,
		Method:       resp.Type,
		Country:      resp.Country,
		ParentHandle: resp.ParentHandle,
		WhoisServer:  resp.Port43,
		Status:       resp.Status,
	}

	dates := eventDates(resp.Events)
	if dates.created == "" || dates.changed == "" {
		return nil
	}
	ipnetrec.CreatedDate = dates.created
	ipnetrec.UpdatedDate = dates.changed

	return nb.plugin.storeRecord(e, asset, ipnetrec)
}
