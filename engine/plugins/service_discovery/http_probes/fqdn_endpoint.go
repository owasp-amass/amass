// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

type fqdnEndpoint struct {
	name   string
	plugin *httpProbing
}

func (fe *fqdnEndpoint) Name() string {
	return fe.name
}

func (fe *fqdnEndpoint) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !e.Session.Config().Active {
		return nil
	}
	if !support.HasDNSRecordType(e, int(dns.TypeCNAME)) &&
		!support.HasDNSRecordType(e, int(dns.TypeA)) &&
		!support.HasDNSRecordType(e, int(dns.TypeAAAA)) {
		return nil
	}
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.Service), fe.name)
	if err != nil {
		return err
	}

	src := fe.plugin.source
	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		findings = append(findings, fe.lookup(e, e.Entity, since)...)
	} else {
		findings = append(findings, fe.query(e, e.Entity)...)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if len(findings) > 0 {
		fe.process(e, findings)
	}
	return nil
}

func (fe *fqdnEndpoint) lookup(e *et.Event, host *dbt.Entity, since time.Time) []*support.Finding {
	var findings []*support.Finding

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().OutgoingEdges(ctx, host, since); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if _, err := e.Session.DB().FindEdgeTags(ctx, edge, since, fe.plugin.source.Name); err != nil {
				continue
			}
			if _, ok := edge.Relation.(*oamgen.PortRelation); ok {
				if srv, err := e.Session.DB().FindEntityById(ctx,
					edge.ToEntity.ID); err == nil && srv != nil && srv.Asset.AssetType() == oam.Service {
					findings = append(findings, &support.Finding{
						From:     host,
						FromName: host.Asset.Key(),
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

func (fe *fqdnEndpoint) query(e *et.Event, host *dbt.Entity) []*support.Finding {
	var findings []*support.Finding

	var count int
	fch := make(chan []*support.Finding, len(e.Session.Config().Scope.Ports))
	for _, port := range e.Session.Config().Scope.Ports {
		count++
		go fe.probeOnePort(e, host, port, fch)
	}

	for range count {
		if results := <-fch; len(results) > 0 {
			findings = append(findings, results...)
		}
	}

	return findings
}

func (fe *fqdnEndpoint) probeOnePort(e *et.Event, host *dbt.Entity, port int, ch chan []*support.Finding) {
	fqdn := host.Asset.(*oamdns.FQDN)
	addr := fqdn.Name + ":" + strconv.Itoa(port)

	ch <- fe.plugin.query(e, host, portScheme(port)+"://"+addr, port)
}

func (fe *fqdnEndpoint) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, fe.plugin.source, fe.plugin.name, fe.name)
}
