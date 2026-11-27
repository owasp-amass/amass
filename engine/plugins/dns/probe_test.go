// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// distinctAsked returns how many of names were asked for. Other queries,
// such as the wildcard test an answer sets off, are not counted.
func distinctAsked(d *plugintest.DNS, names []string) int {
	want := map[string]bool{}
	for _, n := range names {
		want[n+"."] = true
	}

	seen := map[string]bool{}
	for _, q := range d.Queries() {
		if _, name, ok := strings.Cut(q, " "); ok && want[name] {
			seen[name] = true
		}
	}
	return len(seen)
}

// Once three probes below a zone fail outright, the rest of the zone's probes
// are skipped for the session; another zone is still probed, and names that
// do not exist do not count as failures.
func TestProbesStopWhenAZoneStopsAnswering(t *testing.T) {
	sess := plugintest.NewSession(t)
	fake := sess.DNS(t)
	fake.Fail("mail.provider.example")
	fake.Add(t, "_sip._tcp.example.com. 300 IN SRV 0 0 5060 sip.example.com.")

	d := &dnsSubs{name: "DNS-Subdomains", plugin: &dnsPlugin{name: "DNS"}, sessNames: map[string]*subsSession{}}
	e := &et.Event{Session: sess}

	var names []string
	for i := range 40 {
		names = append(names, fmt.Sprintf("_svc%d._tcp.mail.provider.example", i))
	}
	for _, rr := range d.probeAll(e, "mail.provider.example", names, dns.TypeSRV) {
		if rr != nil {
			t.Fatal("a failing zone gave an answer")
		}
	}
	if n := distinctAsked(fake, names); n >= len(names) || n > zoneFailLimit+probeWorkers {
		t.Errorf("%d of %d probes were sent to a zone that stopped answering", n, len(names))
	}
	if _, err := d.probe(e, "mail.provider.example", "_late._tcp.mail.provider.example", dns.TypeSRV); err != errZoneUnresponsive {
		t.Errorf("a later probe of the failing zone = %v, want it skipped", err)
	}

	var good []string
	for i := range 10 {
		good = append(good, fmt.Sprintf("_none%d._tcp.example.com", i))
	}
	good = append(good, "_sip._tcp.example.com")
	answers := d.probeAll(e, "example.com", good, dns.TypeSRV)
	if answers[len(good)-1] == nil {
		t.Error("a zone that answers lost its probe after names that do not exist")
	}
	if n := distinctAsked(fake, good); n != len(good) {
		t.Errorf("%d of %d probes were sent to a zone that answers", n, len(good))
	}
}
