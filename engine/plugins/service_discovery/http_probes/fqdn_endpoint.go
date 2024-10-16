// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"errors"
	"strconv"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
)

type fqdnEndpoint struct {
	name   string
	plugin *httpProbing
}

func (fe *fqdnEndpoint) Name() string {
	return fe.name
}

func (fe *fqdnEndpoint) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !e.Session.Config().Active {
		return nil
	}
	if !fe.checkFQDNResolved(e) {
		return nil
	}
	if _, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 {
		return nil
	}

	src := support.GetSource(e.Session, fe.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.NetworkEndpoint), fe.name)
	if err != nil {
		return err
	}

	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		findings = append(findings, fe.lookup(e, e.Asset, src, since)...)
	} else {
		findings = append(findings, fe.store(e, e.Asset, src)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if len(findings) > 0 {
		fe.process(e, findings, src)
	}
	return nil
}

func (fe *fqdnEndpoint) checkFQDNResolved(e *et.Event) bool {
	for _, rtype := range []string{"cname_record", "a_record", "aaaa_record"} {
		if _, hit := e.Session.Cache().GetRelations(&dbt.Relation{
			FromAsset: e.Asset,
			Type:      rtype,
		}); hit {
			return true
		}
	}
	return false
}

func (fe *fqdnEndpoint) lookup(e *et.Event, asset, src *dbt.Asset, since time.Time) []*support.Finding {
	fqdn := asset.Asset.Key()
	var findings []*support.Finding
	atype := string(oam.NetworkEndpoint)

	for _, port := range e.Session.Config().Scope.Ports {
		name := fqdn + ":" + strconv.Itoa(port)

		endpoints := support.SourceToAssetsWithinTTL(e.Session, name, atype, src, since)
		for _, endpoint := range endpoints {
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: fqdn,
				To:       endpoint,
				ToName:   name,
				Rel:      "port",
			})
		}
	}
	return findings
}

func (fe *fqdnEndpoint) store(e *et.Event, asset, src *dbt.Asset) []*support.Finding {
	var findings []*support.Finding
	fqdn := asset.Asset.(*domain.FQDN)

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		for _, port := range e.Session.Config().Scope.Ports {
			addr := fqdn.Name + ":" + strconv.Itoa(port)

			proto := "https"
			if port == 80 || port == 8080 {
				proto = "http"
			}

			if endpoint, err := e.Session.DB().Create(asset, "port", &domain.NetworkEndpoint{
				Address:  addr,
				Name:     fqdn.Name,
				Port:     port,
				Protocol: proto,
			}); err == nil && endpoint != nil {
				_, _ = e.Session.DB().Link(endpoint, "source", src)
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: fqdn.Name,
					To:       endpoint,
					ToName:   addr,
					Rel:      "port",
				})
			}
		}
	})
	<-done
	close(done)
	return findings
}

func (fe *fqdnEndpoint) process(e *et.Event, findings []*support.Finding, src *dbt.Asset) {
	support.ProcessAssetsWithSource(e, findings, src, fe.plugin.name, fe.name)
}
