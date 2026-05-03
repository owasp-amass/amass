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

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().Probe, &amasshttp.Request{URL: target})
	e.Session.NetSem().Release()

	if err == nil && resp != nil {
		findings = append(findings, hp.store(e, resp, entity, port)...)
	}
	return findings
}

func (hp *httpProbing) store(e *et.Event, resp *amasshttp.Response, entity *dbt.Entity, port int) []*support.Finding {
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

func (hp *httpProbing) createCertificates(sess et.Session, resp *amasshttp.Response) (*dbt.Entity, *x509.Certificate, []*support.Finding) {
	var findings []*support.Finding

	if resp.TLS == nil || !resp.TLS.HandshakeComplete {
		return nil, nil, findings
	}

	count := len(resp.TLS.PeerCertificates)
	if count == 0 {
		return nil, nil, findings
	}

	dur := time.Duration(count*3) * time.Second
	ctx, cancel := context.WithTimeout(sess.Ctx(), dur)
	defer cancel()

	var prev *dbt.Entity
	var firstAsset *dbt.Entity
	var firstCert *x509.Certificate
	// traverse the certificate chain
	for _, cert := range resp.TLS.PeerCertificates {
		c := support.X509ToOAMTLSCertificate(cert)
		if c == nil {
			break
		}

		a, err := sess.DB().CreateAsset(ctx, c)
		if err != nil {
			break
		}

		if prev == nil {
			firstAsset = a
			firstCert = cert
		} else if tls, valid := prev.Asset.(*oamcert.TLSCertificate); valid {
			findings = append(findings, &support.Finding{
				From:     prev,
				FromName: tls.SerialNumber,
				To:       a,
				ToName:   c.SerialNumber,
				ToMeta:   cert,
				Rel:      &oamgen.SimpleRelation{Name: "issuing_certificate"},
			})
		}
		prev = a
	}

	return firstAsset, firstCert, findings
}
