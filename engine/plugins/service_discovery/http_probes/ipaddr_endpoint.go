// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
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
	ip, ok := e.Asset.Asset.(*network.IPAddress)
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
	if !e.Session.Scope().IsAddressInScope(e.Session.Cache(), ip) {
		return nil
	}

	src := support.GetSource(e.Session, r.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.SocketAddress), r.name)
	if err != nil {
		return err
	}

	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		findings = append(findings, r.lookup(e, e.Asset, src, since)...)
	} else {
		findings = append(findings, r.store(e, e.Asset, src)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if len(findings) > 0 {
		r.process(e, findings, src)
	}

	support.IPAddressSweep(e, ip, src, 25, sweepCallback)
	return nil
}

func (r *ipaddrEndpoint) lookup(e *et.Event, asset, src *dbt.Asset, since time.Time) []*support.Finding {
	addr := asset.Asset.Key()
	var findings []*support.Finding
	atype := string(oam.SocketAddress)

	for _, port := range e.Session.Config().Scope.Ports {
		name := addr + ":" + strconv.Itoa(port)

		endpoints := support.SourceToAssetsWithinTTL(e.Session, name, atype, src, since)
		for _, endpoint := range endpoints {
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: addr,
				To:       endpoint,
				ToName:   name,
				Rel:      "port",
			})
		}
	}
	return findings
}

func (r *ipaddrEndpoint) store(e *et.Event, asset, src *dbt.Asset) []*support.Finding {
	var findings []*support.Finding
	ip := asset.Asset.(*network.IPAddress)

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

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

			if endpoint, err := e.Session.DB().Create(asset, "port", &network.SocketAddress{
				Address:   netip.MustParseAddrPort(addr),
				IPAddress: netip.MustParseAddr(ip.Address.String()),
				Port:      port,
				Protocol:  proto,
			}); err == nil && endpoint != nil {
				_, _ = e.Session.DB().Link(endpoint, "source", src)
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: ip.Address.String(),
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

func (r *ipaddrEndpoint) process(e *et.Event, findings []*support.Finding, src *dbt.Asset) {
	support.ProcessAssetsWithSource(e, findings, src, r.plugin.name, r.name)
}

func sweepCallback(e *et.Event, ip *network.IPAddress, src *dbt.Asset) {
	done := make(chan *dbt.Asset, 1)
	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		addr, err := e.Session.DB().Create(nil, "", ip)
		if err == nil && addr != nil {
			_, _ = e.Session.DB().Link(addr, "source", src)
		}
		done <- addr
	})

	if addr := <-done; addr != nil {
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    ip.Address.String(),
			Asset:   addr,
			Session: e.Session,
		})
	}
	close(done)
}
