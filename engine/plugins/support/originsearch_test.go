// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/reversesearch"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// originFixture is a session whose in-scope host serves a favicon
// fingerprint, a fake search source answering with two hosts, and the
// source's plugin.
type originFixture struct {
	sess   *plugintest.Session
	ident  *dbt.Entity
	plugin *originSearch
	hits   *atomic.Int32
	status *atomic.Int32
}

func newOriginFixture(t *testing.T) originFixture {
	t.Helper()
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Scope().AddDomain("example.com")

	host := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	svc := sess.Asset(t, &oamplat.Service{ID: "svc-1", Type: "HTTP"})
	ident := sess.Asset(t, &oamgen.Identifier{UniqueID: "favicon_mmh3:-123", ID: "-123", Type: "favicon_mmh3"})
	sess.Edge(t, host, &oamgen.PortRelation{Name: "port", PortNumber: 443, Protocol: "tcp"}, svc)
	sess.Edge(t, svc, &oamgen.SimpleRelation{Name: "fingerprint"}, ident)

	hits, status := &atomic.Int32{}, &atomic.Int32{}
	status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Query().Get("q") != "favicon:-123" || r.Header.Get("X-Key") != "k1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(`{"matches":[{"ip_str":"192.0.2.10","port":443},{"ip_str":"2001:db8::1","port":80},` +
			`{"ip_str":"not-an-ip","port":80}]}`))
	}))
	t.Cleanup(srv.Close)

	src := OriginSource{
		Name: "TestSearch",
		Query: func(idType, value string) (string, bool) {
			return "favicon:" + value, idType == "favicon_mmh3"
		},
		Request: func(query string, cred *config.Credentials) *amasshttp.Request {
			if cred.Apikey == "" {
				return nil
			}
			return &amasshttp.Request{URL: srv.URL + "/search?q=" + query,
				Header: amasshttp.Header{"X-Key": []string{cred.Apikey}}}
		},
		Parse: reversesearch.ParseShodan,
	}
	return originFixture{sess: sess, ident: ident, plugin: NewOriginSearch(src).(*originSearch), hits: hits,
		status: status}
}

func (f originFixture) credentials(creds map[string]*config.Credentials) {
	f.sess.Config().DataSrcConfigs = &config.DataSourceConfig{Datasources: []*config.DataSource{
		{Name: "TestSearch", Creds: creds}}}
}

func (f originFixture) check(t *testing.T) {
	t.Helper()
	if err := f.plugin.check(&et.Event{Session: f.sess, Entity: f.ident}); err != nil {
		t.Fatal(err)
	}
}

func TestOriginSearchStoresAndEnqueuesHits(t *testing.T) {
	f := newOriginFixture(t)
	// the account without a key is passed over for the one with it
	f.credentials(map[string]*config.Credentials{"a": {Username: "nokey"}, "b": {Apikey: "k1"}})
	f.check(t)

	if f.hits.Load() != 1 {
		t.Fatalf("the source was asked %d times, want once", f.hits.Load())
	}
	ips, err := f.sess.DB().FindEntitiesByType(context.Background(), oam.IPAddress, time.Now().Add(-time.Hour), 10)
	if err != nil || len(ips) != 2 {
		t.Fatalf("stored %d addresses, want 2 (the malformed one skipped): %v", len(ips), err)
	}
	if n := len(f.sess.Enqueued()); n != 2 {
		t.Errorf("enqueued %d addresses, want 2", n)
	}
	for _, ip := range ips {
		tags, _ := f.sess.DB().FindEntityTags(context.Background(), ip, time.Time{})
		sourced := false
		for _, tag := range tags {
			if sp, ok := tag.Property.(*oamgen.SourceProperty); ok && sp.Source == "TestSearch" {
				sourced = true
			}
		}
		if !sourced {
			t.Errorf("%s has no TestSearch source", ip.Asset.Key())
		}
	}

	// asked again within the TTL, the source is not queried
	f.check(t)
	if f.hits.Load() != 1 {
		t.Errorf("the source was asked again within the TTL")
	}
}

func TestOriginSearchSkips(t *testing.T) {
	t.Run("no credentials", func(t *testing.T) {
		f := newOriginFixture(t)
		f.check(t)
		f.credentials(map[string]*config.Credentials{"a": {Username: "nokey"}})
		f.check(t)
		if f.hits.Load() != 0 {
			t.Error("the source was asked without usable credentials")
		}
	})
	t.Run("unsupported fingerprint", func(t *testing.T) {
		f := newOriginFixture(t)
		f.credentials(map[string]*config.Credentials{"a": {Apikey: "k1"}})
		jarm := f.sess.Asset(t, &oamgen.Identifier{UniqueID: "jarm:abc", ID: "abc", Type: "jarm"})
		if err := f.plugin.check(&et.Event{Session: f.sess, Entity: jarm}); err != nil {
			t.Fatal(err)
		}
		if f.hits.Load() != 0 {
			t.Error("the source was asked about a fingerprint type it cannot search")
		}
	})
	t.Run("error answer", func(t *testing.T) {
		f := newOriginFixture(t)
		f.credentials(map[string]*config.Credentials{"a": {Apikey: "k1"}})
		f.status.Store(http.StatusTooManyRequests)
		f.check(t)
		ips, _ := f.sess.DB().FindEntitiesByType(context.Background(), oam.IPAddress, time.Now().Add(-time.Hour), 10)
		if f.hits.Load() != 1 || len(ips) != 0 {
			t.Errorf("an error answer stored %d addresses", len(ips))
		}
	})
	t.Run("not an identifier", func(t *testing.T) {
		f := newOriginFixture(t)
		fqdn := f.sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
		if err := f.plugin.check(&et.Event{Session: f.sess, Entity: fqdn}); err == nil {
			t.Error("a non-Identifier event was accepted")
		}
	})
}
