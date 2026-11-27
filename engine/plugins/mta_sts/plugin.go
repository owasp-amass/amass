// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package mtasts collects a domain's MTA-STS policy. The _mta-sts.<domain> TXT
// record (gathered by the DNS plugin) only announces that a policy exists; the
// policy itself — crucially its enforcement mode — is served over HTTPS at
// mta-sts.<domain>/.well-known/mta-sts.txt. This plugin fetches that file and
// records the mode, max_age and mx hosts as properties of the HTTPS service.
package mtasts

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	"golang.org/x/time/rate"
)

type mtaSTS struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewMTASTS() et.Plugin {
	return &mtaSTS{
		name:   "MTA-STS",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{Name: "MTA-STS", Confidence: 100},
	}
}

func (m *mtaSTS) Name() string { return m.name }

func (m *mtaSTS) Start(r et.Registry) error {
	m.log = r.Log().WithGroup("plugin").With("name", m.name)

	// The DNS plugin stores the policy's existence as a TXT record at
	// _mta-sts.<domain>; this handler fires on that name and fetches the
	// policy from the matching mta-sts.<domain> HTTPS host.
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       m,
		Name:         m.name + "-Handler",
		Position:     40,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.Service), string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     m.check,
	}); err != nil {
		return err
	}

	m.log.Info("Plugin started")
	return nil
}

func (m *mtaSTS) Stop() { m.log.Info("Plugin stopped") }

func (m *mtaSTS) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return nil
	}

	apex, ok := strings.CutPrefix(strings.ToLower(fqdn.Name), "_mta-sts.")
	if !ok || !strings.Contains(apex, ".") {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.Service), m.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, m.source, since) {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, m.source)

	if policy := m.fetch(e, apex); policy != nil {
		m.store(e, apex, policy)
	}
	return nil
}

// STSPolicy is the parsed content of an MTA-STS policy file.
type STSPolicy struct {
	Mode   string
	MaxAge string
	MX     []string
}

func (m *mtaSTS) fetch(e *et.Event, apex string) *STSPolicy {
	_ = support.WaitLimit(e.Session.Ctx(), m.rlimit)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	url := "https://mta-sts." + apex + "/.well-known/mta-sts.txt"
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: url})
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	return ParseSTSPolicy(resp.Body)
}

// ParseSTSPolicy reads an MTA-STS policy file (RFC 8461): CRLF-separated
// "key: value" lines carrying the version (STSv1), the enforcement mode, a
// max_age and one mx pattern per line. It returns nil when the text is not a
// valid STSv1 policy with a mode.
func ParseSTSPolicy(body string) *STSPolicy {
	p := &STSPolicy{}
	var sts bool
	for _, line := range strings.FieldsFunc(body, func(r rune) bool { return r == '\n' || r == '\r' }) {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		switch key {
		case "version":
			sts = strings.EqualFold(val, "STSv1")
		case "mode":
			p.Mode = strings.ToLower(val)
		case "max_age":
			p.MaxAge = val
		case "mx":
			if val != "" {
				p.MX = append(p.MX, strings.ToLower(val))
			}
		}
	}
	if !sts || p.Mode == "" {
		return nil
	}
	return p
}

// store records the policy as properties of the mta-sts.<apex> HTTPS service.
func (m *mtaSTS) store(e *et.Event, apex string, p *STSPolicy) *dbt.Entity {
	host := "mta-sts." + apex

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	hostEnt, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: host})
	if err != nil || hostEnt == nil {
		return nil
	}

	serv := support.ServiceWithIdentifier(host, "tcp", 443)
	serv.Type = "web-service"
	portrel := &oamgen.PortRelation{Name: "tcp_port_443", PortNumber: 443, Protocol: "TCP"}

	s, err := support.CreateServiceAsset(e.Session, hostEnt, portrel, serv, nil)
	if err != nil || s == nil {
		return nil
	}

	m.setProperty(ctx, e, s, "mta_sts_mode", p.Mode)
	if p.MaxAge != "" {
		m.setProperty(ctx, e, s, "mta_sts_max_age", p.MaxAge)
	}
	for _, mx := range p.MX {
		m.setProperty(ctx, e, s, "mta_sts_mx", mx)
	}

	svc, ok := s.Asset.(*oamplat.Service)
	if !ok {
		return s
	}
	// Tag the service's port edge with this source and dispatch it.
	support.ProcessAssetsWithSource(e, []*support.Finding{{
		From: hostEnt, FromName: host, To: s, ToName: "Service: " + svc.ID, Rel: portrel,
	}}, m.source, m.name, m.name+"-Handler")

	e.Session.Log().Info("MTA-STS policy stored", "domain", apex, "mode", p.Mode,
		slog.Group("plugin", "name", m.name, "handler", m.name+"-Handler"))
	return s
}

func (m *mtaSTS) setProperty(ctx context.Context, e *et.Event, entity *dbt.Entity, name, value string) {
	_, _ = e.Session.DB().CreateEntityProperty(ctx, entity,
		&oamgen.SimpleProperty{PropertyName: name, PropertyValue: value})
}
