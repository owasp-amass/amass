// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

func TestCAAData(t *testing.T) {
	caa := &dns.CAA{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}
	if got := caaData(caa); got != `0 issue "letsencrypt.org"` {
		t.Errorf("caaData = %q", got)
	}
}

func TestStoreCAA(t *testing.T) {
	sess := plugintest.NewSession(t)
	d := &dnsSubs{name: "DNS-Subdomains", plugin: &dnsPlugin{name: "DNS"}}
	apex := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	e := &et.Event{Session: sess}

	records := []dns.RR{
		&dns.CAA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
			Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
		&dns.CAA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
			Flag: 0, Tag: "iodef", Value: "mailto:security@example.com"},
	}
	d.storeCAA(e, apex, "example.com", records)

	ctx := context.Background()
	tags, err := sess.DB().FindEntityTags(ctx, apex, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var caa []string
	for _, tag := range tags {
		if p, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && p.Header.RRType == int(dns.TypeCAA) {
			caa = append(caa, p.Data)
		}
	}
	if len(caa) != 2 {
		t.Fatalf("stored CAA records = %v", caa)
	}
}
