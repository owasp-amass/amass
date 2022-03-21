// Copyright © by Jeff Foley 2021-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"testing"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/stringset"
)

func TestNewNames(t *testing.T) {
	expected := stringset.New("owasp.org", "www.owasp.org", "ftp.owasp.org", "mail.owasp.org",
		"dev.owasp.org", "prod.owasp.org", "vpn.owasp.org", "uat.owasp.org", "stage.owasp.org",
		"confluence.owasp.org", "api.owasp.org", "test.owasp.org")
	defer expected.Close()

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

	domain := "owasp.org"
	sys.Config().AddDomain(domain)
	sys.DataSources()[0].Input() <- &requests.DNSRequest{Domain: domain}

	l := expected.Len()
	for i := 0; i < l; i++ {
		req := <-sys.DataSources()[0].Output()

		if d, ok := req.(*requests.DNSRequest); !ok || !expected.Has(d.Name) || d.Domain != domain || d.Tag != "testing" || d.Source != "names" {
			t.Errorf("Name %d: %v was not found in the list of expected names", i+1, d.Name)
		} else {
			expected.Remove(d.Name)
		}
	}
}

func TestNewAddrs(t *testing.T) {
	expected := stringset.New("72.237.4.113", "72.237.4.114", "72.237.4.35", "72.237.4.38", "72.237.4.79",
		"72.237.4.90", "72.237.4.103", "72.237.4.243", "4.26.24.234", "44.193.34.238", "52.206.190.41", "18.211.32.87")
	defer expected.Close()

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

	domain := "owasp.org"
	sys.Config().AddDomain(domain)
	sys.DataSources()[0].Input() <- &requests.DNSRequest{Domain: domain}

	num := expected.Len()
	for i := 0; i < num; i++ {
		req := <-sys.DataSources()[0].Output()

		if a, ok := req.(*requests.AddrRequest); !ok || !expected.Has(a.Address) || a.Domain != domain || a.Tag != "testing" || a.Source != "addrs" {
			t.Errorf("Address %d: %v was not found in the list of expected addresses", i+1, a.Address)
		} else {
			expected.Remove(a.Address)
		}
	}
}

func TestAssociated(t *testing.T) {
	expected := map[string]*requests.WhoisRequest{
		"owasp.org": {
			Domain:     "owasp.org",
			NewDomains: []string{"globalappsec.org"},
			Tag:        "testing",
			Source:     "associated",
		},
		"utica.edu": {
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

	domain := "owasp.org"
	sys.Config().AddDomains(domain, "utica.edu")
	sys.DataSources()[0].Input() <- &requests.WhoisRequest{Domain: domain}

	num := len(expected)
	for i := 0; i < num; i++ {
		req := <-sys.DataSources()[0].Output()

		if a, ok := req.(*requests.WhoisRequest); ok {
			if exp, found := expected[a.Domain]; !found || a.Domain != exp.Domain ||
				a.NewDomains[0] != exp.NewDomains[0] || a.Tag != "testing" || a.Source != "associated" {
				t.Errorf("Incorrect output for associated %d, expected: %s, got: %v", i+1, exp, a)
			}
		}
	}
}
