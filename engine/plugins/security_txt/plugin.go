// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package securitytxt collects a domain's security.txt file (RFC 9116), served
// at /.well-known/security.txt, which names how to report security issues. Its
// fields are recorded against the web service: the Contact entries as a
// ContactRecord, the URL-valued fields (Canonical, Policy, Encryption,
// Acknowledgments, Hiring) as related URLs, and Expires and Preferred-Languages
// as service properties.
package securitytxt

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

type securityTxt struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewSecurityTxt() et.Plugin {
	return &securityTxt{
		name:   "security.txt",
		rlimit: rate.NewLimiter(rate.Every(2*time.Second), 1),
		source: &et.Source{Name: "security.txt", Confidence: 100},
	}
}

func (p *securityTxt) Name() string { return p.name }

func (p *securityTxt) Start(r et.Registry) error {
	p.log = r.Log().WithGroup("plugin").With("name", p.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       p,
		Name:         p.name + "-Handler",
		Position:     40,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{string(oam.Service), string(oam.ContactRecord), string(oam.Identifier),
			string(oam.URL), string(oam.Phone)},
		EventType: oam.FQDN,
		Callback:  p.check,
	}); err != nil {
		return err
	}

	p.log.Info("Plugin started")
	return nil
}

func (p *securityTxt) Stop() { p.log.Info("Plugin stopped") }

func (p *securityTxt) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return nil
	}

	host := strings.ToLower(fqdn.Name)
	// security.txt is published for the registered domain.
	if dom, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil || dom != host {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.Service), p.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, p.source)

	if file := p.fetch(e, host); file != nil {
		p.store(e, e.Entity, host, file)
	}
	return nil
}

func (p *securityTxt) fetch(e *et.Event, host string) *SecurityTxt {
	_ = support.WaitLimit(e.Session.Ctx(), p.rlimit)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	// The well-known location is canonical; the legacy top-level path is a
	// fallback the RFC still allows.
	for _, path := range []string{"/.well-known/security.txt", "/security.txt"} {
		resp, err := amasshttp.RequestWebPage(ctx,
			e.Session.Clients().General, &amasshttp.Request{URL: "https://" + host + path})
		if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
			continue
		}
		if file := ParseSecurityTxt(resp.Body); file != nil {
			return file
		}
	}
	return nil
}

// SecurityTxt is the parsed content of a security.txt file.
type SecurityTxt struct {
	Contacts        []string // raw Contact values (mailto:, https://, tel:)
	Canonical       []string
	Policy          []string
	Encryption      []string
	Acknowledgments []string
	Hiring          []string
	Expires         string
	Languages       string
}

// ParseSecurityTxt reads a security.txt file (RFC 9116): "Field: value" lines,
// case-insensitive field names, one value per line, fields may repeat, and #
// starts a comment. It returns nil when no Contact field is present, which the
// RFC requires.
func ParseSecurityTxt(body string) *SecurityTxt {
	s := &SecurityTxt{}
	for _, line := range strings.FieldsFunc(body, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}

		switch key {
		case "contact":
			s.Contacts = append(s.Contacts, val)
		case "canonical":
			s.Canonical = append(s.Canonical, val)
		case "policy":
			s.Policy = append(s.Policy, val)
		case "encryption":
			s.Encryption = append(s.Encryption, val)
		case "acknowledgments", "acknowledgements":
			s.Acknowledgments = append(s.Acknowledgments, val)
		case "hiring":
			s.Hiring = append(s.Hiring, val)
		case "expires":
			s.Expires = val
		case "preferred-languages":
			s.Languages = val
		}
	}
	if len(s.Contacts) == 0 {
		return nil
	}
	return s
}

func (p *securityTxt) store(e *et.Event, apex *dbt.Entity, host string, file *SecurityTxt) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	serv := support.ServiceWithIdentifier(host, "tcp", 443)
	serv.Type = "web-service"
	portrel := &oamgen.PortRelation{Name: "tcp_port_443", PortNumber: 443, Protocol: "TCP"}

	s, err := support.CreateServiceAsset(e.Session, apex, portrel, serv, nil)
	if err != nil || s == nil {
		return nil
	}
	svc, ok := s.Asset.(*oamplat.Service)
	if !ok {
		return nil
	}

	// The contact record for the whole file, linked from the service.
	cr, err := e.Session.DB().CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: "security.txt for " + host})
	if err == nil && cr != nil {
		p.edge(ctx, e, s, cr, "security_contact")
		for _, c := range file.Contacts {
			p.storeContact(ctx, e, cr, c)
		}
	}

	// The URL-valued fields, each as a related URL.
	for label, urls := range map[string][]string{
		"security_canonical":       file.Canonical,
		"security_policy":          file.Policy,
		"security_encryption":      file.Encryption,
		"security_acknowledgments": file.Acknowledgments,
		"security_hiring":          file.Hiring,
	} {
		for _, raw := range urls {
			if u := support.RawURLToOAM(raw); u != nil {
				if a, err := e.Session.DB().CreateAsset(ctx, u); err == nil && a != nil {
					p.edge(ctx, e, s, a, label)
				}
			}
		}
	}

	if file.Expires != "" {
		p.property(ctx, e, s, "security_txt_expires", file.Expires)
	}
	if file.Languages != "" {
		p.property(ctx, e, s, "security_txt_languages", file.Languages)
	}

	support.ProcessAssetsWithSource(e, []*support.Finding{{
		From: apex, FromName: host, To: s, ToName: "Service: " + svc.ID, Rel: portrel,
	}}, p.source, p.name, p.name+"-Handler")

	e.Session.Log().Info("security.txt stored", "domain", host, "contacts", len(file.Contacts),
		slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
	return s
}

// storeContact records one Contact value under the contact record: a mailto as
// an email identifier, a tel as a phone, and anything else as a URL.
func (p *securityTxt) storeContact(ctx context.Context, e *et.Event, cr *dbt.Entity, value string) {
	switch {
	case strings.HasPrefix(strings.ToLower(value), "mailto:"):
		email := strings.ToLower(strings.TrimPrefix(value[len("mailto:"):], " "))
		if a, err := e.Session.DB().CreateAsset(ctx, &oamgen.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", oamgen.EmailAddress, email), ID: email, Type: oamgen.EmailAddress,
		}); err == nil && a != nil {
			p.edge(ctx, e, cr, a, "id")
		}
	case strings.HasPrefix(strings.ToLower(value), "tel:"):
		if phone := support.PhoneToOAMPhone(strings.TrimPrefix(value[len("tel:"):], " "), "", ""); phone != nil {
			phone.Type = contact.PhoneTypeRegular
			if a, err := e.Session.DB().CreateAsset(ctx, phone); err == nil && a != nil {
				p.edge(ctx, e, cr, a, "phone")
			}
		}
	default:
		if u := support.RawURLToOAM(value); u != nil {
			if a, err := e.Session.DB().CreateAsset(ctx, u); err == nil && a != nil {
				p.edge(ctx, e, cr, a, "url")
			}
		}
	}
}

func (p *securityTxt) edge(ctx context.Context, e *et.Event, from, to *dbt.Entity, label string) {
	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.SimpleRelation{Name: label},
		FromEntity: from,
		ToEntity:   to,
	})
	if err != nil || edge == nil {
		return
	}
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
		Source:     p.source.Name,
		Confidence: p.source.Confidence,
	})
}

func (p *securityTxt) property(ctx context.Context, e *et.Event, entity *dbt.Entity, name, value string) {
	_, _ = e.Session.DB().CreateEntityProperty(ctx, entity,
		&oamgen.SimpleProperty{PropertyName: name, PropertyValue: value})
}
