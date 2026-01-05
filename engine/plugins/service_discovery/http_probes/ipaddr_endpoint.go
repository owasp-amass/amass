// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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
	if !e.Session.Scope().IsAddressInScope(e.Session.DB(), ip) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.Service), r.name)
	if err != nil {
		return err
	}

	src := r.plugin.source
	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		findings = append(findings, r.lookup(e, e.Entity, since)...)
	} else {
		go func() {
			if findings := append(findings, r.query(e, e.Entity)...); len(findings) > 0 {
				r.process(e, findings)
			}
		}()
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if len(findings) > 0 {
		r.process(e, findings)
	}

	support.IPAddressSweep(e, ip, src, 25, sweepCallback)
	return nil
}

func (r *ipaddrEndpoint) lookup(e *et.Event, ip *dbt.Entity, since time.Time) []*support.Finding {
	var findings []*support.Finding

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
	ip := ipaddr.Asset.(*network.IPAddress)

	for _, port := range e.Session.Config().Scope.Ports {
		a := ip.Address.String()
		if ip.Type == "IPv6" {
			a = "[" + a + "]"
		}
		addr := a + ":" + strconv.Itoa(port)

		proto := "https"
		if port == 80 || port == 8080 {
			proto = "http"
		}

		findings = append(findings, r.plugin.query(e, ipaddr, proto+"://"+addr, port)...)
	}

	return findings
}

func (r *ipaddrEndpoint) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, r.plugin.source, r.plugin.name, r.name)
}

func sweepCallback(e *et.Event, ip *network.IPAddress, src *et.Source) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if entity, err := e.Session.DB().CreateAsset(ctx, ip); err == nil && entity != nil {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, entity, &general.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    ip.Address.String(),
			Entity:  entity,
			Session: e.Session,
		})
	}
}
