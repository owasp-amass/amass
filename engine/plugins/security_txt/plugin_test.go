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
	s := p.store(e, apex, "example.com", file)
	if s == nil {
		t.Fatal("the security.txt was not stored")
	}

	ctx := context.Background()
	// Service --security_contact--> ContactRecord --id--> email identifier.
	cedges, err := sess.DB().OutgoingEdges(ctx, s, time.Time{}, "security_contact")
	if err != nil || len(cedges) != 1 {
		t.Fatalf("security_contact edges: %d, %v", len(cedges), err)
	}
	cr, _ := sess.DB().FindEntityById(ctx, cedges[0].ToEntity.ID)
	ids, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "id")
	if err != nil || len(ids) != 1 {
		t.Fatalf("contact id edges: %d, %v", len(ids), err)
	}
	idAsset, _ := sess.DB().FindEntityById(ctx, ids[0].ToEntity.ID)
	if id, ok := idAsset.Asset.(*oamgen.Identifier); !ok || id.ID != "security@example.com" {
		t.Errorf("contact identifier %+v", idAsset.Asset)
	}
	// The https contact is a URL off the contact record.
	if urls, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "url"); err != nil || len(urls) != 1 {
		t.Errorf("contact url edges: %d, %v", len(urls), err)
	}

	// Service --security_policy/security_encryption--> URL.
	for _, label := range []string{"security_policy", "security_encryption"} {
		if edges, err := sess.DB().OutgoingEdges(ctx, s, time.Time{}, label); err != nil || len(edges) != 1 {
			t.Errorf("%s edges: %d, %v", label, len(edges), err)
		}
	}

	// Expires and languages are service properties.
	tags, _ := sess.DB().FindEntityTags(ctx, s, time.Time{})
	got := map[string]string{}
	for _, tag := range tags {
		if sp, ok := tag.Property.(*oamgen.SimpleProperty); ok {
			got[sp.PropertyName] = sp.PropertyValue
		}
	}
	if got["security_txt_expires"] == "" || got["security_txt_languages"] != "en" {
		t.Errorf("service properties = %v", got)
	}
}
