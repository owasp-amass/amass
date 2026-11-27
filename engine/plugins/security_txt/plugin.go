// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package securitytxt collects a domain's security.txt file (RFC 9116), served
// at /.well-known/security.txt, which names how to report security issues. The
// file is stored as its URL, joined to the domain, and what it says as the
// file's ContactRecord (URL --contact--> ContactRecord): the Contact entries as
// the record's email Identifiers, phones and URLs, the URL-valued fields
// (Canonical, Policy, Encryption, Acknowledgments, Hiring) as URLs whose
// relation carries the field name (PropField), and Expires and
// Preferred-Languages as record properties.
package securitytxt

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

// Property names. PropField on a ContactRecord --url--> URL relation names the
// security.txt field the URL came from; a URL without it is a Contact entry.
const (
	PropField     = "security_txt_field"
	PropExpires   = "security_txt_expires"
	PropLanguages = "security_txt_languages"
)

// Paths is where a security.txt is served: the well-known location the RFC
// makes canonical, then the legacy top-level path it still allows.
var Paths = []string{"/.well-known/security.txt", "/security.txt"}

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
		Transforms: []string{string(oam.ContactRecord), string(oam.Identifier), string(oam.URL),
			string(oam.Phone)},
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

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.ContactRecord), p.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, p.source, since) {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, p.source)

	if raw, file := p.fetch(e, host); file != nil {
		p.store(e, e.Entity, raw, file)
	}
	return nil
}

// fetch returns the URL and contents of the first security.txt served at
// Paths, or nil.
func (p *securityTxt) fetch(e *et.Event, host string) (string, *SecurityTxt) {
	for _, path := range Paths {
		raw := "https://" + host + path
		body, err := support.FetchBody(e, raw, p.rlimit, maxFileBytes)
		if err != nil {
			continue
		}
		if file := ParseSecurityTxt(string(body)); file != nil {
			return raw, file
		}
	}
	return "", nil
}

// maxFileBytes bounds a security.txt.
const maxFileBytes = 64 << 10

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

// store records the file's URL, joined to the domain, and what the file says
// as the file's ContactRecord.
func (p *securityTxt) store(e *et.Event, apex *dbt.Entity, raw string, file *SecurityTxt) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()
	sess := e.Session
	db := sess.DB()

	u := support.RawURLToOAM(raw)
	if u == nil {
		return nil
	}
	urlEnt, err := db.CreateAsset(ctx, u)
	if err != nil || urlEnt == nil {
		return nil
	}
	support.AddSource(ctx, sess, urlEnt, p.source)
	support.Link(ctx, sess, urlEnt, "domain", apex, p.source)

	cr := support.LinkContactRecord(ctx, sess, urlEnt, "contact", raw, p.source)
	if cr == nil {
		return nil
	}
	for _, c := range file.Contacts {
		support.LinkContactValue(ctx, sess, cr, c, p.source)
	}

	// The URL-valued fields, each a URL off the record named by its field.
	for field, urls := range map[string][]string{
		"canonical":       file.Canonical,
		"policy":          file.Policy,
		"encryption":      file.Encryption,
		"acknowledgments": file.Acknowledgments,
		"hiring":          file.Hiring,
	} {
		for _, v := range urls {
			ou := support.RawURLToOAM(v)
			if ou == nil {
				continue
			}
			a, err := db.CreateAsset(ctx, ou)
			if err != nil || a == nil {
				continue
			}
			support.AddEdgeProperty(ctx, sess, support.Link(ctx, sess, cr, "url", a, p.source), PropField, field)
		}
	}
	support.AddProperty(ctx, sess, cr, PropExpires, file.Expires)
	support.AddProperty(ctx, sess, cr, PropLanguages, file.Languages)

	sess.Log().Info("security.txt stored", "url", raw, "contacts", len(file.Contacts),
		slog.Group("plugin", "name", p.name, "handler", p.name+"-Handler"))
	return cr
}
