// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"context"
	"crypto/x509"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/service"
)

type interrogation struct {
	name       string
	plugin     *httpProbing
	transforms []string
	mlock      sync.Mutex
	gate       map[string]struct{}
}

func (r *interrogation) Name() string {
	return r.name
}

func (r *interrogation) check(e *et.Event) error {
	atype := e.Asset.Asset.AssetType()
	if atype != oam.NetworkEndpoint && atype != oam.SocketAddress {
		return errors.New("failed to extract the endpoint asset")
	}

	if !e.Session.Config().Active {
		return nil
	}

	src := support.GetSource(e.Session, r.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	matches, err := e.Session.Config().CheckTransformations(string(atype), append(r.transforms, r.plugin.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}
	// all of the transforms must be supported by the config
	for _, transform := range r.transforms {
		if !matches.IsMatch(transform) {
			return nil
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(atype), string(oam.Service), r.plugin.name)
	if err != nil {
		return err
	}

	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		findings = append(findings, r.lookup(e, e.Asset, src, since)...)
	} else {
		findings = append(findings, r.query(e, e.Asset, src)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if len(findings) > 0 {
		r.process(e, findings, src)
	}
	return nil
}

func (r *interrogation) lookup(e *et.Event, asset, src *dbt.Asset, since time.Time) []*support.Finding {
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

func (r *interrogation) query(e *et.Event, asset, src *dbt.Asset) []*support.Finding {
	var findings []*support.Finding

	var addr, host string
	if sa, ok := asset.Asset.(*network.SocketAddress); ok {
		addr = sa.Protocol + "://"
		host = sa.IPAddress.String()

		if sa.Port == 80 || sa.Port == 443 {
			addr += sa.IPAddress.String()
		} else {
			addr += sa.Address.String()
		}
	} else if ne, ok := asset.Asset.(*domain.NetworkEndpoint); ok {
		host = ne.Name
		addr = ne.Protocol + "://"

		if ne.Port == 80 || ne.Port == 443 {
			addr += ne.Name
		} else {
			addr += ne.Address
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if resp, err := http.RequestWebPage(ctx, &http.Request{URL: addr}); err == nil && resp != nil {
		r.blockUntilLocked(host)
		findings = append(findings, r.store(e, resp, asset, src)...)
		r.hostUnlock(host)
	}
	return findings
}

func (r *interrogation) store(e *et.Event, resp *http.Response, asset, src *dbt.Asset) []*support.Finding {
	addr := asset.Asset.Key()
	var findings []*support.Finding

	var firstAsset *dbt.Asset
	var firstCert *x509.Certificate
	if resp.TLS != nil && resp.TLS.HandshakeComplete && len(resp.TLS.PeerCertificates) > 0 {
		done := make(chan struct{}, 1)

		support.AppendToDBQueue(func() {
			defer func() { done <- struct{}{} }()

			if e.Session.Done() {
				return
			}

			var prev *dbt.Asset
			// traverse the certificate chain
			for _, cert := range resp.TLS.PeerCertificates {
				c := support.X509ToOAMTLSCertificate(cert)
				if c == nil {
					break
				}

				a, err := e.Session.DB().Create(prev, "issuing_certificate", c)
				if err != nil {
					break
				}
				_, _ = e.Session.DB().Link(a, "source", src)

				if prev == nil {
					firstAsset = a
					firstCert = cert
				} else {
					tls := prev.Asset.(*oamcert.TLSCertificate)
					findings = append(findings, &support.Finding{
						From:     prev,
						FromName: tls.SerialNumber,
						To:       a,
						ToName:   c.SerialNumber,
						ToMeta:   cert,
						Rel:      "issuing_certificate",
					})
				}
				prev = a
			}
		})
		<-done
		close(done)
	}

	serv := support.ServiceWithIdentifier(&r.plugin.hash, e.Session.ID().String(), addr)
	if serv == nil {
		return findings
	}
	serv.Banner = resp.Body
	serv.BannerLen = int(resp.Length)
	serv.Headers = resp.Header

	var c *oamcert.TLSCertificate
	if firstAsset != nil {
		c = firstAsset.Asset.(*oamcert.TLSCertificate)
	}

	s, err := support.CreateServiceAsset(e.Session, asset, "service", serv, c)
	if err != nil {
		return findings
	}

	serv = s.Asset.(*service.Service)
	findings = append(findings, &support.Finding{
		From:     asset,
		FromName: addr,
		To:       s,
		ToName:   "Service: " + serv.Identifier,
		Rel:      "service",
	})

	if firstAsset != nil && firstCert != nil {
		findings = append(findings, &support.Finding{
			From:     s,
			FromName: "Service: " + serv.Identifier,
			To:       firstAsset,
			ToName:   c.SerialNumber,
			ToMeta:   firstCert,
			Rel:      "certificate",
		})
	}

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()
		_, _ = e.Session.DB().Link(s, "source", src)
		if firstAsset != nil {
			_, _ = e.Session.DB().Link(s, "certificate", firstAsset)
		}
	})
	<-done
	close(done)
	return findings
}

func (r *interrogation) process(e *et.Event, findings []*support.Finding, src *dbt.Asset) {
	support.ProcessAssetsWithSource(e, findings, src, r.plugin.name, r.name)
}

func (r *interrogation) hostLock(host string) bool {
	r.mlock.Lock()
	defer r.mlock.Unlock()

	if host == "" {
		return true
	}
	key := strings.ToLower(host)

	if _, ok := r.gate[key]; ok {
		return false
	}

	r.gate[key] = struct{}{}
	return true
}

func (r *interrogation) hostUnlock(host string) {
	r.mlock.Lock()
	defer r.mlock.Unlock()

	if host == "" {
		return
	}
	key := strings.ToLower(host)

	delete(r.gate, key)
}

func (r *interrogation) blockUntilLocked(host string) {
	if r.hostLock(host) {
		return
	}

	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for range t.C {
		if r.hostLock(host) {
			break
		}
	}
}
