// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package leaks finds credentials and AWS identifiers in what the
// enumeration stored: URLs (their query strings carry keys and pre-signed
// AWS credentials), service banners and response headers, and TXT records
// (internal/secretscan). Other plugins record what they read and do not
// store, such as document text, with a Recorder. An identifier is stored in
// full; a secret as an exposed_secret Identifier of its kind, hash and
// masked preview, with its value sealed in the encrypted secrets store when
// a master key is set. Found credentials are never used or tested.
package leaks

import (
	"context"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/platform"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// Properties of an exposed_secret Identifier.
const (
	PropSecretKind    = "secret_kind"
	PropSecretPreview = "secret_preview"
)

type leaks struct {
	*Recorder
	log *slog.Logger
}

func NewLeaks() et.Plugin {
	return &leaks{Recorder: NewRecorder("Exposed-Secrets", &et.Source{Name: "Exposed-Secrets", Confidence: 90})}
}

func (l *leaks) Name() string { return l.name }

func (l *leaks) Start(r et.Registry) error {
	l.log = r.Log().WithGroup("plugin").With("name", l.name)

	for _, h := range []struct {
		name  string
		atype oam.AssetType
		check func(*et.Event) error
	}{{"URL", oam.URL, l.checkURL}, {"Service", oam.Service, l.checkService}, {"TXT", oam.FQDN, l.checkTXT}} {
		if err := r.RegisterHandler(&et.Handler{
			Plugin:       l,
			Name:         l.name + "-" + h.name + "-Handler",
			Position:     50,
			MaxInstances: support.MidHandlerInstances,
			Transforms:   []string{string(oam.Identifier)},
			EventType:    h.atype,
			Callback:     h.check,
		}); err != nil {
			return err
		}
	}

	l.log.Info("Plugin started")
	return nil
}

func (l *leaks) Stop() { l.log.Info("Plugin stopped") }

func (l *leaks) checkURL(e *et.Event) error {
	u, ok := e.Entity.Asset.(*oamurl.URL)
	if !ok {
		return nil
	}
	text := u.Raw
	if dec, err := url.QueryUnescape(u.Raw); err == nil && dec != u.Raw {
		text += "\n" + dec
	}
	l.Record(e, e.Entity, text)
	return nil
}

func (l *leaks) checkService(e *et.Event) error {
	s, ok := e.Entity.Asset.(*platform.Service)
	if !ok {
		return nil
	}
	var b strings.Builder
	b.WriteString(s.Output)
	keys := make([]string, 0, len(s.Attributes))
	for k := range s.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range s.Attributes[k] {
			b.WriteString("\n" + k + ": " + v)
		}
	}
	l.Record(e, e.Entity, b.String())
	return nil
}

func (l *leaks) checkTXT(e *et.Event) error {
	if _, ok := e.Entity.Asset.(*oamdns.FQDN); !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()
	tags, err := e.Session.DB().FindEntityTags(ctx, e.Entity, time.Time{}, "dns_record")
	if err != nil {
		return nil
	}
	var b strings.Builder
	for _, tag := range tags {
		if p, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && p.Header.RRType == int(dns.TypeTXT) {
			b.WriteString(p.Data + "\n")
		}
	}
	l.Record(e, e.Entity, b.String())
	return nil
}
