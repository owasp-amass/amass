// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package ssh_probes records the SSH host keys of in-scope addresses during
// active enumeration. It completes only the key exchange, never
// authentication: no user name or credential is ever sent.
package ssh_probes

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
)

// sshPorts are the ports probed for SSH.
var sshPorts = []int{22}

type sshProbing struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

// NewSSHProbing returns the SSH host key plugin.
func NewSSHProbing() et.Plugin {
	return &sshProbing{
		name:   "SSH-Probes",
		source: &et.Source{Name: "SSH-Probes", Confidence: 100},
	}
}

func (sp *sshProbing) Name() string {
	return sp.name
}

func (sp *sshProbing) Start(r et.Registry) error {
	sp.log = r.Log().WithGroup("plugin").With("name", sp.name)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       sp,
		Name:         sp.name + "-IPAddress-Interrogation",
		Position:     43,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Service)},
		EventType:    oam.IPAddress,
		Callback:     sp.check,
	}); err != nil {
		return err
	}

	sp.log.Info("Plugin started")
	return nil
}

func (sp *sshProbing) Stop() {
	sp.log.Info("Plugin stopped")
}

func (sp *sshProbing) check(e *et.Event) error {
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

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.Service), sp.name)
	if err != nil || since.IsZero() {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, sp.source, since) {
		return nil
	}

	var findings []*support.Finding
	for _, port := range sshPorts {
		if f := sp.probe(e, e.Entity, ip, port); f != nil {
			findings = append(findings, f)
		}
	}

	support.MarkAssetMonitored(e.Session, e.Entity, sp.source)
	if len(findings) > 0 {
		support.ProcessAssetsWithSource(e, findings, sp.source, sp.name, sp.name+"-IPAddress-Interrogation")
	}
	return nil
}

// probe records the SSH service on ip's port with its banner and host keys.
func (sp *sshProbing) probe(e *et.Event, entity *dbt.Entity, ip *network.IPAddress, port int) *support.Finding {
	dial := amassnet.NewDialContext(dialTimeout)
	addr := net.JoinHostPort(ip.Address.String(), strconv.Itoa(port))
	banner, keys, err := hostKeys(e.Session.Ctx(), func(ctx context.Context, network, address string) (net.Conn, error) {
		e.Session.NetSem().Acquire()
		defer e.Session.NetSem().Release()

		return dial(ctx, network, address)
	}, addr)
	if err != nil || len(keys) == 0 {
		return nil
	}

	serv := support.ServiceWithIdentifier(ip.Address.String(), "tcp", port)
	serv.Type = "ssh"
	serv.Output = banner
	serv.OutputLen = len(banner)
	portrel := &oamgen.PortRelation{Name: "tcp_port_" + strconv.Itoa(port), PortNumber: port, Protocol: "TCP"}

	svc, err := support.CreateServiceAsset(e.Session, entity, portrel, serv, nil)
	if err != nil || svc == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	for _, key := range keys {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, svc, &oamgen.SimpleProperty{
			PropertyName:  fingerprint.SSHHostKey,
			PropertyValue: key,
		})
	}

	return &support.Finding{From: entity, FromName: entity.Asset.Key(), To: svc, ToName: "Service: " + serv.ID,
		Rel: portrel}
}
