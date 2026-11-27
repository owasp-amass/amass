// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

type httpProbing struct {
	name    string
	log     *slog.Logger
	fqdnend *fqdnEndpoint
	ipaddr  *ipaddrEndpoint
	source  *et.Source
}

func NewHTTPProbing() et.Plugin {
	return &httpProbing{
		name: "HTTP-Probes",
		source: &et.Source{
			Name:       "HTTP-Probes",
			Confidence: 100,
		},
	}
}

func (hp *httpProbing) Name() string {
	return hp.name
}

func (hp *httpProbing) Start(r et.Registry) error {
	hp.log = r.Log().WithGroup("plugin").With("name", hp.name)

	hp.fqdnend = &fqdnEndpoint{
		name:   hp.name + "-FQDN-Interrogation",
		plugin: hp,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       hp,
		Name:         hp.fqdnend.name,
		Position:     41,
		Exclusive:    true,
		MaxInstances: support.MidHandlerInstances,
		Transforms: []string{
			string(oam.Service),
			string(oam.TLSCertificate),
		},
		EventType: oam.FQDN,
		Probes:    true,
		Callback:  hp.fqdnend.check,
	}); err != nil {
		return err
	}

	hp.ipaddr = &ipaddrEndpoint{
		name:   hp.name + "-IPAddress-Interrogation",
		plugin: hp,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       hp,
		Name:         hp.ipaddr.name,
		Position:     42,
		Exclusive:    true,
		MaxInstances: support.MidHandlerInstances,
		Transforms: []string{
			string(oam.Service),
			string(oam.TLSCertificate),
		},
		EventType: oam.IPAddress,
		Probes:    true,
		Callback:  hp.ipaddr.check,
	}); err != nil {
		return err
	}

	hp.log.Info("Plugin started")
	return nil
}

func (hp *httpProbing) Stop() {
	hp.log.Info("Plugin stopped")
}

func (hp *httpProbing) query(e *et.Event, entity *dbt.Entity, target string, port int) []*support.Finding {
	var findings []*support.Finding
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), amassnet.ActiveTimeout(e.Session.Ctx(), 15*time.Second))
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().Probe, &amasshttp.Request{URL: target})
	e.Session.NetSem().Release()

	if err == nil && resp != nil {
		findings = append(findings, hp.store(e, resp, entity, port, hp.faviconHash(e, target))...)
	}
	return findings
}

// faviconMaxBytes bounds the favicon body that is hashed; real icons are small,
// and a larger body is an error or default page rather than an icon.
const faviconMaxBytes = 1 << 20

// faviconHash fetches the service's /favicon.ico and returns its hash in the
// convention Shodan and most recon tools use, or "" when there is no usable
// icon. It is stored like the other fingerprints so that services sharing a
// favicon can be found by value — the signal used to locate an origin server
// behind a CDN by its favicon hash.
func (hp *httpProbing) faviconHash(e *et.Event, target string) string {
	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), amassnet.ActiveTimeout(e.Session.Ctx(), 10*time.Second))
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().Probe,
		&amasshttp.Request{URL: target + "/favicon.ico"})
	if err != nil || resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 || len(resp.Body) > faviconMaxBytes {
		return ""
	}

	return fingerprint.FaviconHash([]byte(resp.Body))
}

func (hp *httpProbing) store(e *et.Event, resp *amasshttp.Response, entity *dbt.Entity, port int, favicon string) []*support.Finding {
	addr := entity.Asset.Key()
	serv := support.ServiceWithIdentifier(addr, "tcp", port)

	serv.Type = "web-service"
	serv.Output = resp.Body
	serv.OutputLen = int(resp.Length)
	serv.Attributes = resp.Header

	var c *oamcert.TLSCertificate
	firstAsset, firstCert, findings := hp.createCertificates(e.Session, resp)
	if firstAsset != nil {
		var valid bool
		c, valid = firstAsset.Asset.(*oamcert.TLSCertificate)
		if !valid {
			return findings
		}
	}

	portrel := &oamgen.PortRelation{
		Name:       fmt.Sprintf("tcp_port_%d", port),
		PortNumber: port,
		Protocol:   "TCP",
	}

	s, err := support.CreateServiceAsset(e.Session, entity, portrel, serv, c)
	if err != nil {
		return findings
	}

	serv, valid := s.Asset.(*oamplat.Service)
	if !valid {
		return findings
	}

	hp.storeFingerprints(e, s, resp, favicon)

	// for adding the source information
	findings = append(findings, &support.Finding{
		From:     entity,
		FromName: addr,
		To:       s,
		ToName:   "Service: " + serv.ID,
		Rel:      portrel,
	})

	if firstAsset != nil && firstCert != nil {
		findings = append(findings, &support.Finding{
			From:     s,
			FromName: "Service: " + serv.ID,
			To:       firstAsset,
			ToName:   c.SerialNumber,
			ToMeta:   firstCert,
			Rel:      &oamgen.SimpleRelation{Name: "certificate"},
		})
	}
	return findings
}

// storeFingerprints records the page's web fingerprints (title, analytics
// identifiers, content hash, favicon hash) as shared Identifiers linked from the
// service by a "fingerprint" edge, under the id_types of the fingerprint package
// that every collector shares, so services and hosts sharing a value can be
// found by it.
func (hp *httpProbing) storeFingerprints(e *et.Event, svc *dbt.Entity, resp *amasshttp.Response, favicon string) {
	fps := fingerprint.FromHTTP(resp.Header, resp.Body)
	if favicon != "" {
		fps = append(fps, fingerprint.Fingerprint{Name: fingerprint.FaviconMMH3, Value: favicon})
	}

	for _, fp := range fps {
		support.StoreFingerprint(e, svc, hp.source, fp.Name, fp.Value)
	}
}

func (hp *httpProbing) createCertificates(sess et.Session, resp *amasshttp.Response) (*dbt.Entity, *x509.Certificate, []*support.Finding) {
	if resp.TLS == nil || !resp.TLS.HandshakeComplete {
		return nil, nil, nil
	}

	return support.CreateCertificateChain(sess, resp.TLS.PeerCertificates)
}
