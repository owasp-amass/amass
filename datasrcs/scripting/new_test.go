// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"testing"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/requests"
	"github.com/owasp-amass/config/config"
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

		if d, ok := req.(*requests.DNSRequest); !ok || !expected.Has(d.Name) || d.Domain != domain {
			t.Errorf("Name %d: %v was not found in the list of expected names", i+1, d.Name)
		} else {
			expected.Remove(d.Name)
		}
	}
}

func TestSendDNSRecords(t *testing.T) {
	script, sys := setupMockScriptEnv(`
		name="dns_records"
		type="testing"

		function vertical(ctx, domain)
			send_dns_records(ctx, domain, { {
				['rrname']=domain,
				['rrtype']=1,
				['rrdata']="8.8.8.8",
			}})
		end
	`)
	if script == nil || sys == nil {
		t.Fatal("failed to initialize the scripting environment")
	}
	defer func() { _ = sys.Shutdown() }()

	sys.Config().MinimumTTL = 1440
	cfg := sys.Config()
	if cfg == nil {
		t.Fatal("Config is nil")
	}

	if cfg.DataSrcConfigs == nil {
		cfg.DataSrcConfigs = &config.DataSourceConfig{
			GlobalOptions: make(map[string]int),
		}
	}

	dsc := cfg.GetDataSourceConfig(script.String())
	if dsc == nil {
		dsc = &config.DataSource{Name: script.String()} // Initialize if GetDataSourceConfig returns nil
		cfg.DataSrcConfigs.Datasources = append(cfg.DataSrcConfigs.Datasources, dsc)
	}

	dsc.TTL = 1440

	sys.Config().AddDomain("owasp.org")
	script.Input() <- &requests.DNSRequest{Domain: "owasp.org"}

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	select {
	case <-timer.C:
		t.Error("test timed out")
	case req := <-script.Output():
		if ans, ok := req.(*requests.DNSRequest); !ok || ans.Name != "owasp.org" ||
			len(ans.Records) == 0 || ans.Records[0].Name != "owasp.org" ||
			ans.Records[0].Type != 1 || ans.Records[0].Data != "8.8.8.8" {
			t.Error("send DNS records failed")
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

		if a, ok := req.(*requests.AddrRequest); !ok || !expected.Has(a.Address) || a.Domain != domain {
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
		},
		"utica.edu": {
			Domain:     "utica.edu",
			NewDomains: []string{"necyber.com"},
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
			if exp, found := expected[a.Domain]; !found || a.Domain != exp.Domain || a.NewDomains[0] != exp.NewDomains[0] {
				t.Errorf("Incorrect output for associated %d, expected: %s, got: %v", i+1, exp, a)
			}
		}
	}
}
