// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"errors"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
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
	if !support.HasDNSRecordType(e, int(dns.TypeA)) &&
		!support.HasDNSRecordType(e, int(dns.TypeAAAA)) &&
		!support.HasDNSRecordType(e, int(dns.TypeCNAME)) {
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
		findings = append(findings, fe.lookup(e, e.Entity, src, since)...)
	} else {
		findings = append(findings, fe.query(e, e.Entity)...)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if len(findings) > 0 {
		fe.process(e, findings, src)
	}
	return nil
}

func (fe *fqdnEndpoint) lookup(e *et.Event, host *dbt.Entity, src *et.Source, since time.Time) []*support.Finding {
	var findings []*support.Finding

	if edges, err := e.Session.Cache().OutgoingEdges(host, since, "port"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if _, err := e.Session.Cache().GetEdgeTags(edge, since, src.Name); err != nil {
				continue
			}
			if _, ok := edge.Relation.(*general.PortRelation); ok {
				if srv, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && srv != nil && srv.Asset.AssetType() == oam.Service {
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
	fqdn := host.Asset.(*oamdns.FQDN)

	for _, port := range e.Session.Config().Scope.Ports {
		addr := fqdn.Name + ":" + strconv.Itoa(port)

		proto := "https"
		if port == 80 || port == 8080 {
			proto = "http"
		}

		findings = append(findings, fe.plugin.query(e, host, proto+"://"+addr, port)...)
	}

	return findings
}

func (fe *fqdnEndpoint) process(e *et.Event, findings []*support.Finding, src *et.Source) {
	support.ProcessAssetsWithSource(e, findings, src, fe.plugin.name, fe.name)
}
