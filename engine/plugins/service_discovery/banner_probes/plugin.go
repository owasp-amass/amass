// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package banner_probes records the services in-scope addresses announce in
// the greeting a server sends on connection (SMTP, FTP, POP3, IMAP), over TLS
// on the implicit TLS ports, during active enumeration. It reads the
// greeting and closes the connection: no command or credential is ever sent.
package banner_probes

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
)

type bannerProbing struct {
	name   string
	log    *slog.Logger
	source *et.Source
	cat    catalog
}

// NewBannerProbing returns the greeting banner plugin.
func NewBannerProbing() et.Plugin {
	return &bannerProbing{
		name:   "Banner-Probes",
		source: &et.Source{Name: "Banner-Probes", Confidence: 100},
	}
}

func (bp *bannerProbing) Name() string {
	return bp.name
}

func (bp *bannerProbing) Start(r et.Registry) error {
	bp.log = r.Log().WithGroup("plugin").With("name", bp.name)

	cat, err := loadCatalog()
	if err != nil {
		return err
	}
	bp.cat = cat

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       bp,
		Name:         bp.name + "-IPAddress-Interrogation",
		Position:     43,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Service)},
		EventType:    oam.IPAddress,
		Callback:     bp.check,
	}); err != nil {
		return err
	}

	bp.log.Info("Plugin started")
	return nil
}

func (bp *bannerProbing) Stop() {
	bp.log.Info("Plugin stopped")
}

func (bp *bannerProbing) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*network.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}
	if !e.Session.Config().Active {
		return nil
	}
	if reserved, _ := amassnet.IsReservedAddress(ip.Address.String()); reserved {
		return nil
	}
	if _, conf := e.Session.Scope().IsAssetInScope(ip, 0); conf <= 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.Service), bp.name)
	if err != nil || since.IsZero() {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, bp.source, since) {
		return nil
	}

	var findings []*support.Finding
	for _, port := range bp.cat.probedPorts() {
		findings = append(findings, bp.probe(e, e.Entity, ip, port)...)
	}

	support.MarkAssetMonitored(e.Session, e.Entity, bp.source)
	if len(findings) > 0 {
		support.ProcessAssetsWithSource(e, findings, bp.source, bp.name, bp.name+"-IPAddress-Interrogation")
	}
	return nil
}

// probe reads the greeting on ip's port and records the service it
// announces, with the certificate it presented on a TLS port.
func (bp *bannerProbing) probe(e *et.Event, entity *dbt.Entity, ip *network.IPAddress, port int) []*support.Finding {
	dial := amassnet.NewDialContext(dialTimeout)
	addr := net.JoinHostPort(ip.Address.String(), strconv.Itoa(port))
	line, certs, err := readGreeting(e.Session.Ctx(), func(ctx context.Context, network, address string) (net.Conn, error) {
		e.Session.NetSem().Acquire()
		defer e.Session.NetSem().Release()

		return dial(ctx, network, address)
	}, addr, bp.cat.tlsPort(port))
	if err != nil {
		return nil
	}

	p, ok := bp.cat.classify(port, line)
	if !ok {
		bp.log.Debug("unrecognized greeting", "address", addr, "greeting", line)
		return nil
	}

	serv := support.ServiceWithIdentifier(ip.Address.String(), "tcp", port)
	serv.Type = p.ServiceType
	serv.Output = line
	serv.OutputLen = len(line)
	portrel := &oamgen.PortRelation{Name: "tcp_port_" + strconv.Itoa(port), PortNumber: port, Protocol: "TCP"}

	leaf, leafCert, findings := support.CreateCertificateChain(e.Session, certs)
	var cert *oamcert.TLSCertificate
	if leaf != nil {
		cert, _ = leaf.Asset.(*oamcert.TLSCertificate)
	}

	svc, err := support.CreateServiceAsset(e.Session, entity, portrel, serv, cert)
	if err != nil || svc == nil {
		return findings
	}

	findings = append(findings, &support.Finding{From: entity, FromName: entity.Asset.Key(), To: svc,
		ToName: "Service: " + serv.ID, Rel: portrel})
	if cert != nil {
		findings = append(findings, &support.Finding{From: svc, FromName: "Service: " + serv.ID, To: leaf,
			ToName: cert.SerialNumber, ToMeta: leafCert, Rel: &oamgen.SimpleRelation{Name: "certificate"}})
	}
	return findings
}
