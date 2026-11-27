// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/url"
)

func email(t *testing.T, sess *plugintest.Session, addr string) *et.Event {
	ent := sess.Asset(t, &general.Identifier{UniqueID: "email:" + addr, ID: addr, Type: general.EmailAddress})
	return &et.Event{Session: sess, Entity: ent}
}

func TestEmailExpansion(t *testing.T) {
	sess := plugintest.NewSession(t)
	ee := NewEmails().(*emailexpand)

	e := email(t, sess, "Hostmaster@Example.COM")
	findings := ee.store(e, e.Entity)
	if len(findings) != 2 {
		t.Fatalf("findings %+v", findings)
	}
	if cr, ok := findings[0].To.Asset.(*contact.ContactRecord); !ok ||
		findings[0].Rel.Label() != "registration_agency" ||
		cr.DiscoveredAt != "example.com" {
		t.Errorf("contact record finding %+v", findings[0])
	}
	if fqdn, ok := findings[1].To.Asset.(*oamdns.FQDN); !ok || fqdn.Name != "example.com" ||
		findings[1].Rel.Label() != "fqdn" {
		t.Errorf("domain finding %+v (the domain of an address is case-insensitive)", findings[1].To.Asset)
	}

	for _, bad := range []string{"no-at-sign", "two@at@signs", "nobody@", "@example.com"} {
		e := email(t, sess, bad)
		if f := ee.store(e, e.Entity); len(f) != 0 {
			t.Errorf("%q gave findings %+v", bad, f)
		}
	}
}

func TestURLExpansionStore(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(1440)
	u := NewURLs().(*urlexpand)

	m, err := sess.Config().CheckTransformations(string(oam.URL), string(oam.FQDN), string(oam.IPAddress))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		raw, host, kind, label, key string
	}{
		{"https://www.example.com/a", "www.example.com", string(oam.FQDN), "domain", "www.example.com"},
		{"http://192.0.2.7:8080/", "192.0.2.7", string(oam.IPAddress), "ip_address", "192.0.2.7"},
		{"https://[2001:db8::7]/", "2001:db8::7", string(oam.IPAddress), "ip_address", "2001:db8::7"},
	} {
		ent := sess.Asset(t, &url.URL{Raw: tc.raw, Scheme: "https", Host: tc.host, Path: "/"})
		f := u.store(&et.Event{Session: sess, Entity: ent}, tc.kind, ent, m)
		if len(f) != 1 || f[0].Rel.Label() != tc.label || f[0].To.Asset.Key() != tc.key {
			t.Errorf("%s: findings %+v", tc.raw, f)
			continue
		}
		if ip, ok := f[0].To.Asset.(*oamnet.IPAddress); ok {
			if want := map[bool]string{true: "IPv6", false: "IPv4"}[ip.Address.Is6()]; ip.Type != want {
				t.Errorf("%s: address type %s, want %s", tc.raw, ip.Type, want)
			}
		}
	}
}
