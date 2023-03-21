// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net"
	"reflect"
	"sort"
	"testing"

	"github.com/go-ini/ini"
)

func TestConfigAddDomains(t *testing.T) {
	type args struct {
		domains []string
	}
	tests := []struct {
		name      string
		args      args
		wantFound bool
	}{
		{
			name:      "success",
			args:      args{[]string{"utica.edu", "www.utica.edu"}},
			wantFound: true,
		},
		{
			name:      "empty space",
			args:      args{[]string{"  "}},
			wantFound: false,
		},
		{
			name:      "missing label",
			args:      args{[]string{"owasp"}},
			wantFound: false,
		},
		{
			name:      "empty label",
			args:      args{[]string{"owasp."}},
			wantFound: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(Config)
			c.AddDomains(tt.args.domains...)
			for _, d := range tt.args.domains {
				var found bool
				for _, d2 := range c.Domains() {
					if d == d2 {
						found = true
					}
				}
				if !found && tt.wantFound {
					t.Errorf("Config.AddDomains() error = domain %v missing from config.domains", d)
				}
			}
		})
	}
}

func TestConfigParseIPsParseRange(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		p       *parseIPs
		args    args
		wantErr bool
	}{
		{
			name:    "basic success - full range",
			p:       new(parseIPs),
			args:    args{s: "192.168.0.1-192.168.0.3"},
			wantErr: false,
		},
		{
			name:    "basic success - short-hand range",
			p:       new(parseIPs),
			args:    args{s: "192.168.0.1-4"},
			wantErr: false,
		},
		{
			name:    "illicit split",
			p:       new(parseIPs),
			args:    args{s: "192.168.0.1"},
			wantErr: true,
		},
		{
			name:    "illicit range",
			p:       new(parseIPs),
			args:    args{s: "192.168.0.255-192.168.0.260"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.parseRange(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("parseIPs.parseRange() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigParseIPsString(t *testing.T) {
	tests := []struct {
		name string
		p    *parseIPs
		want string
	}{
		{
			name: "success",
			p:    &parseIPs{net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.2"), net.ParseIP("192.168.0.3")},
			want: "192.168.0.1,192.168.0.2,192.168.0.3",
		},
		{
			name: "empty parseIPs",
			p:    new(parseIPs),
			want: "",
		},
		{
			name: "nil parseIPs",
			p:    nil,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("parseIPs.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigParseIPsSet(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		p       *parseIPs
		args    args
		wantErr bool
	}{
		{
			name: "success",
			p:    new(parseIPs),
			args: args{
				s: "192.168.0.1,192.168.0.2,192.168.0.3",
			},
			wantErr: false,
		},
		{
			name: "illicit range",
			p:    new(parseIPs),
			args: args{
				s: "192.168.0.4-",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Set(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("parseIPs.Set() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigBlacklistSubdomain(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		domains []string
	}{
		{
			name:    "blacklist success",
			config:  new(Config),
			domains: []string{"user", "tmp", "admin"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, d := range tt.domains {
				tt.config.BlacklistSubdomain(d)
			}

			sort.Strings(tt.domains)
			sort.Strings(tt.config.Blacklist)

			if !reflect.DeepEqual(tt.domains, tt.config.Blacklist) {
				t.Errorf("BlacklistSubdomain() wanted %v, got %v", tt.domains, tt.config.Blacklist)
			}
		})
	}
}

func TestLoadScopeSettings(t *testing.T) {
	type args struct {
		cfg []byte
	}

	tests := []struct {
		name          string
		args          args
		wantErr       bool
		assertionFunc func(*testing.T, *Config)
	}{
		{
			name: "no error - scope section missing",
			args: args{cfg: []byte(`
			#[missing-scope]
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "failure - invalid address or range",
			args: args{cfg: []byte(`
			[scope]
			address = (invalid value)
			`)},
			wantErr: true,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "failure - invalid address range",
			args: args{cfg: []byte(`
			[scope]
			address = 1.2.3.4-1.1.1.1
			`)},
			wantErr: true,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "success - valid IPv4 addresses",
			args: args{cfg: []byte(`
			[scope]
			address = 1.2.3.4,0.0.0.0,255.255.255.255 ; 01.102.103.104
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if len(c.Addresses) != 3 {
					t.Errorf("Config.loadScopeSettings() - failed to load addresses")
				}
			},
		},
		{
			name: "success - valid IPv6 addresses",
			args: args{cfg: []byte(`
			[scope]
			address = ::,1111:2222:3333:4444:5555:6666:7777:8888,1:2:0001:deca:f000:00c0:ff:ee ; ::1234:5678:1.2.3.4
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if len(c.Addresses) != 3 {
					t.Errorf("Config.loadScopeSettings() - failed to load addresses %v", c.Addresses)
				}
			},
		},
		{
			name: "success - valid address range",
			args: args{cfg: []byte(`
			[scope]
			address = 1.2.3.4-1.2.3.5
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if len(c.Addresses) != 2 {
					t.Errorf("Config.loadScopeSettings() - failed to collect ips from range")
				}
			},
		},
		{
			name: "failure - invalid cidr",
			args: args{cfg: []byte(`
			[scope]
			cidr = (invalid value)
			`)},
			wantErr: true,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "success - valid cidr",
			args: args{cfg: []byte(`
			[scope]
			cidr = 1.2.3.4/8
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if len(c.CIDRs) != 1 {
					t.Errorf("Config.loadScopeSettings() - failed to load cidr")
				}
			},
		},
		{
			name: "no error - invalid asn",
			args: args{cfg: []byte(`
			[scope]
			asn = (invalid value)
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "success - valid asn",
			args: args{cfg: []byte(`
			[scope]
			asn = 26808
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "no error - invalid domain in scope domains",
			args: args{cfg: []byte(`
			[scope.domains]
			domain = (invalid value)
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "success - valid domain in scope domains",
			args: args{cfg: []byte(`
			[scope]
			[scope.domains]
			domain = owasp.org
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "no error - invalid subdomain in section scope.blacklisted",
			args: args{cfg: []byte(`
			[scope]
			[scope.blacklisted]
			subdomain = (invalid value)
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "success - valid subdomain in section scope.blacklisted",
			args: args{cfg: []byte(`
			[scope.blacklisted]
			subdomain = gopher.example.com
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(Config)
			iniFile, err := ini.Load(tt.args.cfg)
			if err != nil {
				t.Errorf("Config.loadScopeSettings() %v error = %v", tt.name, err)
			}

			if err := c.loadScopeSettings(iniFile); (err != nil) != tt.wantErr {
				t.Errorf("Config.loadScopeSettings() %v error = %v", tt.name, err)
			}

			tt.assertionFunc(t, c)
		})
	}
}
