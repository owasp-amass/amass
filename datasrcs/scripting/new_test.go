// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package scripting

import (
	"testing"
	"time"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/stringset"
)

func TestNewNames(t *testing.T) {
	expected := []string{"owasp.org", "www.owasp.org", "ftp.owasp.org", "mail.owasp.org",
		"dev.owasp.org", "prod.owasp.org", "vpn.owasp.org", "uat.owasp.org", "stage.owasp.org",
		"confluence.owasp.org", "api.owasp.org", "test.owasp.org"}

	ctx, sys := setupMockScriptEnv(`
		name="names"
		type="testing"

		function vertical(ctx, domain)
			new_name(ctx, "owasp.org")

			local content = [[
				www.owasp.org
				www.owasp.org
				www.owasp.org
				www.owasp.org
				www.owasp.org
				ftp.owasp.org
				mail.owasp.org
				dev.owasp.org
				prod.owasp.org
				vpn.owasp.org
				uat.owasp.org
				stage.owasp.org
				confluence.owasp.org
				api.owasp.org
				test.owasp.org
			]]
			send_names(ctx, content)
		end
	`)
	if ctx == nil || sys == nil {
		t.Fatal("Failed to initialize the scripting environment")
	}
	defer func() { _ = sys.Shutdown() }()

	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		t.Fatal("Failed to obtain the config and event bus")
	}

	num := len(expected)
	ch := make(chan *requests.DNSRequest, num)
	fn := func(req *requests.DNSRequest) {
		ch <- req
	}

	bus.Subscribe(requests.NewNameTopic, fn)
	defer bus.Unsubscribe(requests.NewNameTopic, fn)

	domain := "owasp.org"
	cfg.AddDomain(domain)
	sys.DataSources()[0].Request(ctx, &requests.DNSRequest{Domain: domain})

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
loop:
	for i := 0; i < num; i++ {
		select {
		case <-timer.C:
			t.Error("The test timed out")
			break loop
		case req := <-ch:
			if exp := expected[i]; req.Name != exp ||
				req.Domain != domain || req.Tag != "testing" || req.Source != "names" {
				t.Errorf("Incorrect output for name %d, expected: %s, got: %v", i+1, exp, req)
			}
		}
	}
}

func TestNewAddrs(t *testing.T) {
	expected := []string{"72.237.4.113", "72.237.4.114", "72.237.4.35", "72.237.4.38", "72.237.4.79",
		"72.237.4.90", "72.237.4.103", "72.237.4.243", "4.26.24.234", "44.193.34.238", "52.206.190.41", "18.211.32.87"}

	ctx, sys := setupMockScriptEnv(`
		name="addrs"
		type="testing"

		function vertical(ctx, domain)
			local addrs = {"72.237.4.113", "72.237.4.114", "72.237.4.35", 
				"72.237.4.38", "72.237.4.79", "72.237.4.90", "72.237.4.103", 
				"72.237.4.243", "4.26.24.234", "44.193.34.238", "52.206.190.41", "18.211.32.87"}

			for _, addr in ipairs(addrs) do
				new_addr(ctx, addr, domain)
    		end
		end
	`)
	if ctx == nil || sys == nil {
		t.Fatal("Failed to initialize the scripting environment")
	}
	defer func() { _ = sys.Shutdown() }()

	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		t.Fatal("Failed to obtain the config and event bus")
	}

	num := len(expected)
	ch := make(chan *requests.AddrRequest, num)
	fn := func(req *requests.AddrRequest) {
		ch <- req
	}

	bus.Subscribe(requests.NewAddrTopic, fn)
	defer bus.Unsubscribe(requests.NewAddrTopic, fn)

	domain := "owasp.org"
	cfg.AddDomain(domain)
	sys.DataSources()[0].Request(ctx, &requests.DNSRequest{Domain: domain})

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
loop:
	for i := 0; i < num; i++ {
		select {
		case <-timer.C:
			t.Error("The test timed out")
			break loop
		case req := <-ch:
			if exp := expected[i]; req.Address != exp ||
				req.Domain != domain || req.Tag != "testing" || req.Source != "addrs" {
				t.Errorf("Incorrect output for address %d, expected: %s, got: %v", i+1, exp, req)
			}
		}
	}
}

func TestNewASNs(t *testing.T) {
	expected := []requests.ASNRequest{
		{
			Address:     "72.237.4.113",
			ASN:         26808,
			Prefix:      "72.237.4.0/24",
			Description: "UTICA-COLLEGE - Utica College",
			Netblocks:   stringset.New("72.237.4.0/24"),
			Tag:         "testing",
			Source:      "asns",
		},
		{
			Address:     "104.16.0.1",
			ASN:         13335,
			Prefix:      "104.16.0.0/14",
			CC:          "US",
			Registry:    "ARIN",
			Description: "CLOUDFLARENET - Cloudflare, Inc.",
			Netblocks:   stringset.New("104.16.0.0/14", "2606:4700::/47"),
			Tag:         "testing",
			Source:      "asns",
		},
	}

	ctx, sys := setupMockScriptEnv(`
		name="asns"
		type="testing"

		function asn(ctx, addr, asn)
			new_asn(ctx, {
				addr="72.237.4.113",
				['asn']=26808,
				prefix="72.237.4.0/24",
				desc="UTICA-COLLEGE - Utica College",
				netblocks={"72.237.4.0/24"},
			})

			new_asn(ctx, {
				addr="104.16.0.1",
				['asn']=13335,
				prefix="104.16.0.0/14",
				cc="US",
				registry="ARIN",
				desc="CLOUDFLARENET - Cloudflare, Inc.",
				netblocks={
					"104.16.0.0/14",
					"2606:4700::/47",
				},
			})

			new_asn(ctx, {
				addr="not.a.valid.addr",
				['asn']=15169,
				prefix="172.217.0.0/19",
				desc="GOOGLE - Google LLC",
				netblocks={
					"172.217.0.0/19",
					"2607:f8b0:4004::/48",
				},
			})

			new_asn(ctx, {
				addr="52.8.0.1",
				['asn']=16509,
				prefix="52.8.0.0/invalid",
				desc="AMAZON-02 - Amazon.com, Inc.",
				netblocks={
					"52.8.0.0/13",
					"50.18.0.0/16",
				},
			})

			new_asn(ctx, {
				addr="162.242.128.1",
				['asn']=33070,
				prefix="162.242.128.0/19",
				desc="",
				netblocks={"162.242.128.0/19"},
			})
		end
	`)
	if ctx == nil || sys == nil {
		t.Fatal("Failed to initialize the scripting environment")
	}
	defer func() { _ = sys.Shutdown() }()

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		t.Fatal("Failed to obtain the event bus")
	}

	num := len(expected)
	ch := make(chan *requests.ASNRequest, num)
	fn := func(req *requests.ASNRequest) {
		ch <- req
	}

	bus.Subscribe(requests.NewASNTopic, fn)
	defer bus.Unsubscribe(requests.NewASNTopic, fn)

	address := "72.237.4.113"
	sys.DataSources()[0].Request(ctx, &requests.ASNRequest{Address: address})

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
loop:
	for i := 0; i < num; i++ {
		select {
		case <-timer.C:
			t.Error("The test timed out")
			break loop
		case req := <-ch:
			if exp := expected[i]; !matchingASNs(req, &exp) {
				t.Errorf("Incorrect output for ASN %d, expected: %v, got: %v", i+1, exp, req)
			}
		}
	}
}

func matchingASNs(first, second *requests.ASNRequest) bool {
	match := true

	if addr := first.Address; addr == "" || addr != second.Address {
		match = false
	}
	if asn := first.ASN; asn == 0 || asn != second.ASN {
		match = false
	}
	if prefix := first.Prefix; prefix == "" || prefix != second.Prefix {
		match = false
	}
	if cc := first.CC; cc != "" && cc != second.CC {
		match = false
	}
	if reg := first.Registry; reg != "" && reg != second.Registry {
		match = false
	}
	if desc := first.Description; desc == "" || desc != second.Description {
		match = false
	}

	nb := first.Netblocks
	if nb.Len() == 0 {
		match = false
	}

	nb.Subtract(second.Netblocks)
	if nb.Len() != 0 {
		match = false
	}

	if tag := first.Tag; tag == "" || tag != second.Tag {
		match = false
	}
	if src := first.Source; src == "" || src != second.Source {
		match = false
	}

	return match
}

func TestAssociated(t *testing.T) {
	expected := []requests.WhoisRequest{
		{
			Domain:     "owasp.org",
			NewDomains: []string{"globalappsec.org"},
			Tag:        "testing",
			Source:     "associated",
		},
		{
			Domain:     "utica.edu",
			NewDomains: []string{"necyber.com"},
			Tag:        "testing",
			Source:     "associated",
		},
	}

	ctx, sys := setupMockScriptEnv(`
		name="associated"
		type="testing"

		function horizontal(ctx, domain)
			local assocs = {
				{
					Domain="owasp.org",
					Assoc="globalappsec.org",
				},
				{
					Domain="utica.edu",
					Assoc="necyber.com",
				},
			}

			for _, a in ipairs(assocs) do
				associated(ctx, a.Domain, a.Assoc)
    		end
		end
	`)
	if ctx == nil || sys == nil {
		t.Fatal("Failed to initialize the scripting environment")
	}
	defer func() { _ = sys.Shutdown() }()

	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		t.Fatal("Failed to obtain the config and event bus")
	}

	num := len(expected)
	ch := make(chan *requests.WhoisRequest, num)
	fn := func(req *requests.WhoisRequest) {
		ch <- req
	}

	bus.Subscribe(requests.NewWhoisTopic, fn)
	defer bus.Unsubscribe(requests.NewWhoisTopic, fn)

	domain := "owasp.org"
	cfg.AddDomains(domain, "utica.edu")
	sys.DataSources()[0].Request(ctx, &requests.WhoisRequest{Domain: domain})

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
loop:
	for i := 0; i < num; i++ {
		select {
		case <-timer.C:
			t.Error("The test timed out")
			break loop
		case req := <-ch:
			if exp := expected[i]; req.Domain != exp.Domain ||
				req.NewDomains[0] != exp.NewDomains[0] || req.Tag != "testing" || req.Source != "associated" {
				t.Errorf("Incorrect output for associated %d, expected: %s, got: %v", i+1, exp, req)
			}
		}
	}
}
