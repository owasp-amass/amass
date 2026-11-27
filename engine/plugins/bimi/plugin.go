// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package bimi reads a domain's Brand Indicators for Message Identification
// (BIMI) record and the mark certificate it names. A BIMI record
// (default._bimi.<domain> TXT, "v=BIMI1; l=<logo>; a=<evidence>") points to a
// Verified Mark Certificate or Common Mark Certificate: an X.509 certificate a
// certification authority issues only after verifying the organization as for
// Extended Validation and, for a registered mark, its trademark registration.
//
// A mark certificate that lists the domain is stored like any TLS certificate
// (the certificate handler records its domains and its subject, the
// CA-verified organization), so it feeds the certificate signals. The mark
// details it carries go on the certificate's subject ContactRecord: the
// trademark registration and the Legal Entity Identifier as Identifiers, and
// the mark type and word mark as properties.
package bimi

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

// Properties this plugin stores on the mark certificate's subject
// ContactRecord. The BIMI record's logo is the record's URL (ContactRecord
// --url--> URL), and the trademark office is the trademark Identifier's
// issuing authority (Identifier --issuing_authority--> ContactRecord
// --organization--> Organization).
const (
	PropMarkType   = "mark_type"
	PropWordMark   = "word_mark"
	maxEvidenceLen = 256 << 10
)

// Mark certificate subject attributes (BIMI Group, Verified Mark Certificate
// Requirements v1.5, section 7.1.4.2.2); the extended key usage is
// support.OIDBIMIKeyUsage.
var (
	oidTrademarkOffice  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 2}
	oidTrademarkCountry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 3}
	oidTrademarkID      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 4}
	oidLEI              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 5}
	oidWordMark         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 6}
	oidMarkType         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 53087, 1, 13}
)

type bimiPlugin struct {
	name   string
	log    *slog.Logger
	source *et.Source
	rlimit *rate.Limiter
}

func NewBIMI() et.Plugin {
	return &bimiPlugin{
		name:   "BIMI",
		source: &et.Source{Name: "BIMI", Confidence: 100},
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
	}
}

func (b *bimiPlugin) Name() string { return b.name }

func (b *bimiPlugin) Start(r et.Registry) error {
	b.log = r.Log().WithGroup("plugin").With("name", b.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       b,
		Name:         b.name + "-Handler",
		Position:     41,
		MaxInstances: support.MinHandlerInstances,
		Transforms: []string{string(oam.TLSCertificate), string(oam.ContactRecord), string(oam.Identifier),
			string(oam.URL), string(oam.Organization)},
		EventType: oam.FQDN,
		Callback:  b.check,
	}); err != nil {
		return err
	}

	b.log.Info("Plugin started")
	return nil
}

func (b *bimiPlugin) Stop() { b.log.Info("Plugin stopped") }

func (b *bimiPlugin) check(e *et.Event) error {
	apex, err := support.InScopeApexToCheck(e, oam.TLSCertificate, b.source, b.name)
	if err != nil || apex == "" {
		return err
	}

	rec, ok := b.record(e, apex)
	if !ok || rec.evidence == "" {
		return nil
	}
	cert := b.fetch(e, rec.evidence, apex)
	if cert == nil {
		return nil
	}
	b.store(e, cert, rec)
	return nil
}

// bimiRecord is a BIMI assertion record's tags.
type bimiRecord struct {
	logo, evidence string
}

// parseBIMI reads a BIMI assertion record: "v=BIMI1" first, then
// semicolon-separated tags, of which l= is the logo and a= the authority
// evidence (the mark certificate).
func parseBIMI(txt string) (bimiRecord, bool) {
	var r bimiRecord
	parts := strings.Split(txt, ";")
	if len(parts) == 0 || !strings.EqualFold(strings.ReplaceAll(strings.TrimSpace(parts[0]), " ", ""), "v=BIMI1") {
		return r, false
	}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "l":
			r.logo = v
		case "a":
			r.evidence = v
		}
	}
	return r, true
}

// record asks for the domain's default BIMI assertion record.
func (b *bimiPlugin) record(e *et.Event, apex string) (bimiRecord, bool) {
	rr, err := support.PerformQuery(e.Session.Ctx(), "default._bimi."+apex, dns.TypeTXT)
	if err != nil {
		return bimiRecord{}, false
	}
	for _, r := range rr {
		if t, ok := r.(*dns.TXT); ok {
			if rec, ok := parseBIMI(strings.Join(t.Txt, "")); ok {
				return rec, true
			}
		}
	}
	return bimiRecord{}, false
}

// fetch downloads the evidence document and returns the mark certificate in
// it that lists the domain, or nil.
func (b *bimiPlugin) fetch(e *et.Event, u, apex string) *x509.Certificate {
	if !strings.HasPrefix(strings.ToLower(u), "https://") {
		return nil
	}
	body, err := support.FetchBody(e, u, b.rlimit, maxEvidenceLen)
	if err != nil {
		return nil
	}
	return markCertificate(body, apex, time.Now())
}

// markCertificate returns the first certificate in a PEM evidence document
// that is a mark certificate (the BIMI extended key usage), lists the domain
// among its names, and is valid at now.
func markCertificate(data []byte, apex string, now time.Time) *x509.Certificate {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			continue
		}
		if !slices.ContainsFunc(cert.UnknownExtKeyUsage, support.OIDBIMIKeyUsage.Equal) {
			continue
		}
		if slices.ContainsFunc(cert.DNSNames, func(n string) bool { return strings.EqualFold(n, apex) }) {
			return cert
		}
	}
}

// markDetails are what a mark certificate's subject says about the mark.
type markDetails struct {
	office, country, trademark, lei, wordMark, markType string
}

func subjectDetails(cert *x509.Certificate) markDetails {
	var d markDetails
	for _, atv := range cert.Subject.Names {
		v, ok := atv.Value.(string)
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch {
		case atv.Type.Equal(oidTrademarkOffice):
			d.office = v
		case atv.Type.Equal(oidTrademarkCountry):
			d.country = strings.ToUpper(v)
		case atv.Type.Equal(oidTrademarkID):
			d.trademark = v
		case atv.Type.Equal(oidLEI):
			d.lei = strings.ToUpper(v)
		case atv.Type.Equal(oidWordMark):
			d.wordMark = v
		case atv.Type.Equal(oidMarkType):
			d.markType = v
		}
	}
	return d
}

// store records the mark certificate and hands it to the certificate handler,
// which stores its names and subject, then adds the mark details to the
// subject ContactRecord.
func (b *bimiPlugin) store(e *et.Event, cert *x509.Certificate, rec bimiRecord) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()
	db := e.Session.DB()

	c := support.X509ToOAMTLSCertificate(cert)
	if c == nil {
		return
	}
	certEnt, err := db.CreateAsset(ctx, c)
	if err != nil || certEnt == nil {
		return
	}
	support.AddSource(ctx, e.Session, certEnt, b.source)

	cr := support.LinkContactRecord(ctx, e.Session, certEnt, "subject_contact",
		support.X509ContactKey(cert, "Subject"), b.source)
	if cr != nil {
		d := subjectDetails(cert)
		support.AddProperty(ctx, e.Session, cr, PropMarkType, d.markType)
		support.AddProperty(ctx, e.Session, cr, PropWordMark, d.wordMark)
		if u := support.RawURLToOAM(rec.logo); u != nil {
			support.LinkAsset(ctx, e.Session, cr, "url", u, b.source)
		}
		if d.trademark != "" && d.country != "" {
			ident := support.LinkAsset(ctx, e.Session, cr, "id", &general.Identifier{
				UniqueID: general.TrademarkRegistration + ":" + d.country + ":" + d.trademark,
				ID:       d.country + ":" + d.trademark, Type: general.TrademarkRegistration}, b.source)
			if ident != nil && d.office != "" {
				b.storeOffice(ctx, e, cert, ident, d.office)
			}
		}
		if d.lei != "" {
			support.LinkAsset(ctx, e.Session, cr, "id", &general.Identifier{UniqueID: general.LEICode + ":" + d.lei,
				ID: d.lei, Type: general.LEICode}, b.source)
		}
	}

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    fmt.Sprintf("TLSCertificate: %s", c.SerialNumber),
		Meta:    cert,
		Entity:  certEnt,
		Session: e.Session,
	})
	e.Session.Log().Info("mark certificate found", "domain", strings.Join(cert.DNSNames, ","),
		"organization", strings.Join(cert.Subject.Organization, ","),
		slog.Group("plugin", "name", b.name, "handler", b.name+"-Handler"))
}

// storeOffice records the trademark office the certificate names as the
// trademark registration's issuing authority.
func (b *bimiPlugin) storeOffice(ctx context.Context, e *et.Event, cert *x509.Certificate, ident *dbt.Entity,
	office string) {
	cr := support.LinkContactRecord(ctx, e.Session, ident, "issuing_authority",
		support.X509ContactKey(cert, "Trademark Office"), b.source)
	if cr != nil {
		_, _ = org.CreateOrgAsset(e.Session, cr, &general.SimpleRelation{Name: "organization"},
			&oamorg.Organization{Name: office}, b.source)
	}
}
