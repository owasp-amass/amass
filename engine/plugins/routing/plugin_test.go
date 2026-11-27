// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/semantics"
	"golang.org/x/time/rate"
)

const statWhois = `{"data": {"authorities": ["ripe"], "irr_records": [
 [{"key": "route", "value": "192.0.2.0/24"}, {"key": "descr", "value": "Acme"}, {"key": "origin", "value": "64500"},
  {"key": "mnt-by", "value": "MAINT-ACME"}, {"key": "mnt-by", "value": "RIPE-NCC-END-MNT"}, {"key": "source", "value": "RIPE"}],
 [{"key": "route", "value": "192.0.2.128/25"}, {"key": "origin", "value": "AS64500"},
  {"key": "mnt-by", "value": "maint-acme"}, {"key": "source", "value": "RIPE"}],
 [{"key": "route", "value": "192.0.0.0/16"}, {"key": "origin", "value": "64511"},
  {"key": "mnt-by", "value": "MAINT-UPSTREAM"}, {"key": "source", "value": "RADB"}],
 [{"key": "route", "value": "198.51.100.0/24"}, {"key": "origin", "value": "64500"}]
]}}`

func TestParseStatWhoisAndMaintainers(t *testing.T) {
	objs, err := parseStatWhois([]byte(statWhois))
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 3 {
		t.Fatalf("want 3 complete route objects, got %d: %+v", len(objs), objs)
	}
	if objs[1].origin != 64500 || objs[1].maintainers[0] != "MAINT-ACME" {
		t.Errorf("object %+v", objs[1])
	}

	r := &routingRecords{catalog: semantics.RoutingRegistryCatalog()}
	got := r.maintainers(objs, netip.MustParsePrefix("192.0.2.0/24"))
	// the registry's maintainer and the upstream's covering aggregate give none
	if len(got) != 1 || got[0].id() != "RIPE:MAINT-ACME" {
		t.Errorf("maintainers %+v", got)
	}
}

func TestParseRPSL(t *testing.T) {
	text := "% This is the RADb whois server\n\n" +
		"route:      192.0.2.0/24\ndescr:      Acme\n            continued\norigin:     AS64500\n" +
		"mnt-by:     MAINT-ACME\nsource:     RADB\n\n" +
		"route6:     2001:db8::/32\norigin:     AS64500\nmnt-by:     MAINT-ACME\nsource:     RADB\n\n" +
		"mntner:     MAINT-ACME\nmnt-by:     MAINT-ACME\nsource:     RADB\n"
	got := parseRPSL(text)
	if len(got) != 2 || got[0].prefix.String() != "192.0.2.0/24" || got[1].prefix.String() != "2001:db8::/32" ||
		got[0].origin != 64500 || got[1].source != "RADB" {
		t.Fatalf("routes %+v", got)
	}
}

func TestParseRPKIValidation(t *testing.T) {
	data := `{"data": {"validating_roas": [
	  {"origin": "64500", "prefix": "192.0.2.0/23", "max_length": 24, "validity": "valid"},
	  {"origin": 64511, "prefix": "192.0.2.0/23", "max_length": 23, "validity": "invalid_length"}],
	 "status": "valid", "resource": "64500", "prefix": "192.0.2.0/24"}}`
	status, roas, err := parseRPKIValidation([]byte(data))
	if err != nil || status != "valid" || len(roas) != 2 {
		t.Fatalf("status %q, roas %+v, err %v", status, roas, err)
	}
	p := netip.MustParsePrefix("192.0.2.0/24")
	if !roas[0].covers(p) || roas[1].covers(p) {
		t.Error("covers misjudges the ROAs' maximum lengths")
	}
	if roas[1].origin != 64511 {
		t.Errorf("a numeric origin was not read: %+v", roas[1])
	}
}

// TestLiveRoutingSources checks the RIPEstat and RADb answers still parse,
// against the RIPE NCC's own prefix. It needs network access, so it runs only
// with AMASS_LIVE_ROUTING=1.
func TestLiveRoutingSources(t *testing.T) {
	if os.Getenv("AMASS_LIVE_ROUTING") == "" {
		t.Skip("set AMASS_LIVE_ROUTING=1 to check the live routing sources")
	}
	c := semantics.RoutingRegistryCatalog()
	client := &http.Client{Timeout: time.Minute}
	get := func(u string) []byte {
		resp, err := client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return b
	}

	objs, err := parseStatWhois(get(c.StatAPI + "/whois/data.json?resource=193.0.0.0/21&sourceapp=" + c.SourceApp))
	if err != nil || len(objs) == 0 {
		t.Fatalf("whois: %d route objects, %v", len(objs), err)
	}
	t.Logf("whois: %d route objects, first %+v", len(objs), objs[0])

	status, roas, err := parseRPKIValidation(get(c.StatAPI +
		"/rpki-validation/data.json?resource=AS3333&prefix=193.0.0.0/21&sourceapp=" + c.SourceApp))
	if err != nil || status == "" {
		t.Fatalf("rpki: status %q, %v", status, err)
	}
	t.Logf("rpki: %s, %d ROAs", status, len(roas))

	r := &routingRecords{catalog: c, rlimit: rate.NewLimiter(rate.Inf, 1)}
	text, err := r.whois(context.Background(), "-s RADB -i mnt-by MAINT-AS3333")
	if err != nil {
		t.Fatalf("irr whois: %v", err)
	}
	t.Logf("irr whois: %d route objects in %d bytes (%q...)", len(parseRPSL(text)), len(text),
		strings.SplitN(text, "\n", 2)[0])
}
