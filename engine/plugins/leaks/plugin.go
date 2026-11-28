// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package leaks finds credentials and AWS identifiers in what the
// enumeration stored: URLs (their query strings carry keys and pre-signed
// AWS credentials), service banners and response headers, and TXT records
// (internal/secretscan). An identifier is stored in full; a secret as an
// exposed_secret Identifier of its kind, hash and masked preview, with its
// value sealed in the encrypted secrets store when a master key is set.
// Found credentials are never used or tested.
package leaks

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/secrets"
	"github.com/owasp-amass/amass/v5/internal/secretscan"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/platform"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// Properties of an exposed_secret Identifier.
const (
	PropSecretKind    = "secret_kind"
	PropSecretPreview = "secret_preview"
)

type leaks struct {
	name   string
	log    *slog.Logger
	source *et.Source
	// vault returns the session database's secrets store, or nil when no
	// master key is set.
	vault func(et.Session) *secrets.Store

	mu    sync.Mutex
	key   *secrets.Key
	keyed bool
}

func NewLeaks() et.Plugin {
	l := &leaks{name: "Exposed-Secrets", source: &et.Source{Name: "Exposed-Secrets", Confidence: 90}}
	l.vault = l.store
	return l
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

// store opens the session database's secrets store under the master key
// from the environment, loaded once.
func (l *leaks) store(sess et.Session) *secrets.Store {
	l.mu.Lock()
	if !l.keyed {
		l.keyed = true
		if k, err := secrets.LoadKey(os.LookupEnv); err == nil {
			l.key = k
		}
	}
	key := l.key
	l.mu.Unlock()
	if key == nil {
		return nil
	}
	return secrets.Open(sess.DB(), key)
}

func (l *leaks) checkURL(e *et.Event) error {
	u, ok := e.Entity.Asset.(*oamurl.URL)
	if !ok {
		return nil
	}
	text := u.Raw
	if dec, err := url.QueryUnescape(u.Raw); err == nil && dec != u.Raw {
		text += "\n" + dec
	}
	l.record(e, text)
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
	l.record(e, b.String())
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
	l.record(e, b.String())
	return nil
}

// record stores what text discloses, linked from the event's asset.
func (l *leaks) record(e *et.Event, text string) {
	finds := secretscan.Scan(text)
	if len(finds) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	var vault *secrets.Store
	for _, f := range finds {
		if !f.Secret() {
			id := l.disclose(ctx, e, &general.Identifier{UniqueID: f.IDType + ":" + f.Value, ID: f.Value,
				Type: f.IDType})
			if f.IDType == general.AWSAccessKeyID {
				l.accountOf(ctx, e, id, f.Value)
			}
			continue
		}

		id := l.disclose(ctx, e, &general.Identifier{UniqueID: general.ExposedSecret + ":" + f.Kind + ":" + f.Hash,
			ID: f.Kind + ":" + f.Hash, Type: general.ExposedSecret})
		if id == nil {
			continue
		}
		support.AddProperty(ctx, e.Session, id, PropSecretKind, f.Kind)
		support.AddProperty(ctx, e.Session, id, PropSecretPreview, f.Preview)
		if vault == nil {
			vault = l.vault(e.Session)
		}
		if vault != nil {
			_ = vault.PutFound(f.Kind, f.Hash, f.Value, l.name)
		}
		e.Session.Log().Info("exposed credential found", "kind", f.Kind, "preview", f.Preview,
			"in", e.Entity.Asset.Key(), slog.Group("plugin", "name", l.name))
	}
}

// disclose stores an Identifier the event's asset discloses.
func (l *leaks) disclose(ctx context.Context, e *et.Event, id *general.Identifier) *dbt.Entity {
	return support.LinkAsset(ctx, e.Session, e.Entity, "discloses", id, l.source)
}

// accountOf links an AWS access key ID to the account it carries.
func (l *leaks) accountOf(ctx context.Context, e *et.Event, keyID *dbt.Entity, value string) {
	if keyID == nil {
		return
	}
	if acct := secretscan.AWSAccountFromKeyID(value); acct != "" {
		_ = support.LinkAsset(ctx, e.Session, keyID, "cloud_account", &general.Identifier{
			UniqueID: general.AWSAccountID + ":" + acct, ID: acct, Type: general.AWSAccountID}, l.source)
	}
}
