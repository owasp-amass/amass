// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
)

type ipaddrEndpoint struct {
	name   string
	plugin *httpProbing
}

func (r *ipaddrEndpoint) Name() string {
	return r.name
}

func (r *ipaddrEndpoint) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*network.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	if !e.Session.Config().Active {
		return nil
	}

	addrstr := ip.Address.String()
	if reserved, _ := amassnet.IsReservedAddress(addrstr); reserved {
		return nil
	}

	// only perform the probe if the address is in scope
	if _, conf := e.Session.Scope().IsAssetInScope(ip, 0); conf <= 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.Service), r.name)
	if err != nil || since.IsZero() {
		return err
	}

	src := r.plugin.source
	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		findings = append(findings, r.lookup(e, e.Entity, since)...)
	} else {
		findings = append(findings, r.query(e, e.Entity)...)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if len(findings) > 0 {
		r.process(e, findings)
	}
	return nil
}

func (r *ipaddrEndpoint) lookup(e *et.Event, ip *dbt.Entity, since time.Time) []*support.Finding {
	var findings []*support.Finding

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().OutgoingEdges(ctx, ip, since); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if _, err := e.Session.DB().FindEdgeTags(ctx, edge, since, r.plugin.source.Name); err != nil {
				continue
			}
			if _, ok := edge.Relation.(*general.PortRelation); ok {
				if srv, err := e.Session.DB().FindEntityById(ctx,
					edge.ToEntity.ID); err == nil && srv != nil && srv.Asset.AssetType() == oam.Service {
					findings = append(findings, &support.Finding{
						From:     ip,
						FromName: ip.Asset.Key(),
						To:       srv,
						ToName:   srv.Asset.Key(),
						Rel:      edge.Relation,
					})
				}
			}
		}
	}
	return findings
}

func (r *ipaddrEndpoint) query(e *et.Event, ipaddr *dbt.Entity) []*support.Finding {
	var findings []*support.Finding

	var count int
	fch := make(chan []*support.Finding, len(e.Session.Config().Scope.Ports))
	for _, port := range e.Session.Config().Scope.Ports {
		count++
		go r.probeOnePort(e, ipaddr, port, fch)
	}

	for range count {
		if results := <-fch; len(results) > 0 {
			findings = append(findings, results...)
		}
	}

	return findings
}

func (r *ipaddrEndpoint) probeOnePort(e *et.Event, ipaddr *dbt.Entity, port int, ch chan []*support.Finding) {
	ip := ipaddr.Asset.(*network.IPAddress)

	a := ip.Address.String()
	if ip.Type == "IPv6" {
		a = "[" + a + "]"
	}
	addr := a + ":" + strconv.Itoa(port)

	ch <- r.plugin.query(e, ipaddr, portScheme(port)+"://"+addr, port)
}

func (r *ipaddrEndpoint) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)
}
