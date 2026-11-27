// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lookalike

import (
	"testing"

	"github.com/miekg/dns"
)

func TestHasType(t *testing.T) {
	ns := &dns.NS{Hdr: dns.RR_Header{Rrtype: dns.TypeNS}, Ns: "ns1.example.net."}
	mx := &dns.MX{Hdr: dns.RR_Header{Rrtype: dns.TypeMX}, Mx: "mx.example.net."}
	if !hasType([]dns.RR{mx, ns}, dns.TypeNS) || hasType([]dns.RR{mx}, dns.TypeNS) || hasType(nil, dns.TypeNS) {
		t.Error("hasType")
	}
	if p := NewLookalikes(); p.Name() != "Lookalike-Domains" {
		t.Errorf("name %s", p.Name())
	}
}
