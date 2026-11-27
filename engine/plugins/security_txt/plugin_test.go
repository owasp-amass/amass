// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package securitytxt

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

func TestParseSecurityTxt(t *testing.T) {
	body := "# the org's security.txt\r\n" +
		"Contact: mailto:security@example.com\r\n" +
		"Contact: https://example.com/report\r\n" +
		"Contact: tel:+1-201-555-0123\r\n" +
		"Canonical: https://example.com/.well-known/security.txt\r\n" +
		"Policy: https://example.com/security-policy\r\n" +
		"Encryption: https://example.com/pgp-key.txt\r\n" +
		"Expires: 2027-01-01T00:00:00.000Z\r\n" +
		"Preferred-Languages: en, fr\r\n"

	s := ParseSecurityTxt(body)
	if s == nil {
		t.Fatal("a valid security.txt was not parsed")
	}
	if len(s.Contacts) != 3 || len(s.Canonical) != 1 || len(s.Policy) != 1 || len(s.Encryption) != 1 ||
		s.Expires == "" || s.Languages != "en, fr" {
		t.Fatalf("parsed %+v", s)
	}

	// A file with no Contact field is invalid per RFC 9116.
	if ParseSecurityTxt("Policy: https://example.com/p\n") != nil {
		t.Error("a file with no Contact was parsed")
	}
}

func TestStore(t *testing.T) {
	sess := plugintest.NewSession(t)
	p := NewSecurityTxt().(*securityTxt)
	apex := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	e := &et.Event{Session: sess, Entity: apex, Dispatcher: &plugintest.Dispatcher{}}

	file := &SecurityTxt{
		Contacts:   []string{"mailto:security@example.com", "https://example.com/report"},
		Policy:     []string{"https://example.com/security-policy"},
		Encryption: []string{"https://example.com/pgp-key.txt"},
		Expires:    "2027-01-01T00:00:00Z",
		Languages:  "en",
	}
	cr := p.store(e, apex, "https://example.com/.well-known/security.txt", file)
	if cr == nil {
		t.Fatal("the security.txt was not stored")
	}

	ctx := context.Background()
	// URL --contact--> ContactRecord, and URL --domain--> the apex.
	in, err := sess.DB().IncomingEdges(ctx, cr, time.Time{}, "contact")
	if err != nil || len(in) != 1 {
		t.Fatalf("contact edges: %d, %v", len(in), err)
	}
	fileURL, _ := sess.DB().FindEntityById(ctx, in[0].FromEntity.ID)
	if u, ok := fileURL.Asset.(*oamurl.URL); !ok || u.Path != "/.well-known/security.txt" {
		t.Fatalf("file URL %+v", fileURL.Asset)
	}
	if doms, err := sess.DB().OutgoingEdges(ctx, fileURL, time.Time{}, "domain"); err != nil || len(doms) != 1 ||
		doms[0].ToEntity.ID != apex.ID {
		t.Errorf("domain edges: %v, %v", doms, err)
	}

	// ContactRecord --id--> email identifier.
	ids, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "id")
	if err != nil || len(ids) != 1 {
		t.Fatalf("contact id edges: %d, %v", len(ids), err)
	}
	idAsset, _ := sess.DB().FindEntityById(ctx, ids[0].ToEntity.ID)
	if id, ok := idAsset.Asset.(*oamgen.Identifier); !ok || id.ID != "security@example.com" {
		t.Errorf("contact identifier %+v", idAsset.Asset)
	}

	// The https contact and the two URL fields are URLs off the record; only
	// the fields' relations carry the field name.
	urls, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "url")
	if err != nil || len(urls) != 3 {
		t.Fatalf("url edges: %d, %v", len(urls), err)
	}
	fields := map[string]bool{}
	for _, ue := range urls {
		tags, _ := sess.DB().FindEdgeTags(ctx, ue, time.Time{}, PropField)
		for _, tag := range tags {
			if sp, ok := tag.Property.(*oamgen.SimpleProperty); ok {
				fields[sp.PropertyValue] = true
			}
		}
	}
	if len(fields) != 2 || !fields["policy"] || !fields["encryption"] {
		t.Errorf("field-tagged URLs = %v", fields)
	}

	// Expires and languages are record properties.
	tags, _ := sess.DB().FindEntityTags(ctx, cr, time.Time{})
	got := map[string]string{}
	for _, tag := range tags {
		if sp, ok := tag.Property.(*oamgen.SimpleProperty); ok {
			got[sp.PropertyName] = sp.PropertyValue
		}
	}
	if got[PropExpires] == "" || got[PropLanguages] != "en" {
		t.Errorf("record properties = %v", got)
	}
}
