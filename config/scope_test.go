// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
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
			c := NewConfig() // Use NewConfig() instead of new(Config)
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
		p       *ParseIPs
		args    args
		wantErr bool
	}{
		{
			name:    "basic success - full range",
			p:       new(ParseIPs),
			args:    args{s: "192.168.0.1-192.168.0.3"},
			wantErr: false,
		},
		{
			name:    "basic success - short-hand range",
			p:       new(ParseIPs),
			args:    args{s: "192.168.0.1-4"},
			wantErr: false,
		},
		{
			name:    "illicit split",
			p:       new(ParseIPs),
			args:    args{s: "192.168.0.1"},
			wantErr: false,
		},
		{
			name:    "illicit range",
			p:       new(ParseIPs),
			args:    args{s: "192.168.0.255-192.168.0.260"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.parseRange(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("ParseIPs.parseRange() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigParseIPsString(t *testing.T) {
	tests := []struct {
		name string
		p    *ParseIPs
		want string
	}{
		{
			name: "success",
			p:    &ParseIPs{net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.2"), net.ParseIP("192.168.0.3")},
			want: "192.168.0.1,192.168.0.2,192.168.0.3",
		},
		{
			name: "empty ParseIPs",
			p:    new(ParseIPs),
			want: "",
		},
		{
			name: "nil ParseIPs",
			p:    nil,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.String(); got != tt.want {
				t.Errorf("ParseIPs.String() = %v, want %v", got, tt.want)
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
		p       *ParseIPs
		args    args
		wantErr bool
	}{
		{
			name: "success",
			p:    new(ParseIPs),
			args: args{
				s: "192.168.0.1,192.168.0.2,192.168.0.3",
			},
			wantErr: false,
		},
		{
			name: "illicit range",
			p:    new(ParseIPs),
			args: args{
				s: "192.168.0.4-",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.Set(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("ParseIPs.Set() error = %v, wantErr %v", err, tt.wantErr)
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
			config:  NewConfig(), // Use NewConfig() instead of new(Config)
			domains: []string{"user", "tmp", "admin"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, d := range tt.domains {
				tt.config.BlacklistSubdomain(d)
			}

			sort.Strings(tt.domains)
			sort.Strings(tt.config.Scope.Blacklist)

			if !reflect.DeepEqual(tt.domains, tt.config.Scope.Blacklist) {
				t.Errorf("BlacklistSubdomain() wanted %v, got %v", tt.domains, tt.config.Scope.Blacklist)
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
			name: "failure - invalid address range",
			args: args{cfg: []byte(`
scope:
  ips:
    - 1.2.3.4-1.1.1.1`)},
			wantErr: true,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "success - valid IPv4 addresses",
			args: args{cfg: []byte(`
scope:
  ips:
    - 1.2.3.4
    - 0.0.0.0
    - 255.255.255.255`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if len(c.Scope.Addresses) != 3 {
					t.Errorf("failed to load addresses")
				}
			},
		},
		{
			name: "success - valid IPv6 addresses",
			args: args{cfg: []byte(`
scope:
  ips:
    - '::'
    - '1111:2222:3333:4444:5555:6666:7777:8888'
    - '1:2:0001:deca:f000:00c0:ff:ee'`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if len(c.Scope.Addresses) != 3 {
					t.Errorf("failed to load addresses %v", c.Scope.Addresses)
				}
			},
		},
		{
			name: "success - valid cidr",
			args: args{cfg: []byte(`
scope:
  cidrs:
    - 1.2.3.4/8`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if len(c.Scope.CIDRStrings) != 1 {
					t.Errorf("failed to load cidr")
				}
			},
		},
		{
			name: "success - valid asn",
			args: args{cfg: []byte(`
scope:
  asns:
    - 26808`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "success - valid domain in scope domains",
			args: args{cfg: []byte(`
scope:
  domains:
    - owasp.org`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "success - valid subdomain in section scope.blacklisted",
			args: args{cfg: []byte(`
scope:
  blacklist:
    - gopher.example.com`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "success - valid ports in section with range in scope.PortsRaw",
			args: args{cfg: []byte(`
scope:
  ports: # ports to be used when actively reaching a service
    - "80"
    - 443
    - 8080-8088`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if len(c.Scope.Ports) != 11 {
					t.Errorf("failed to load ports")
				}
				expected := map[int]struct{}{
					80:   {},
					443:  {},
					8080: {},
					8081: {},
					8082: {},
					8083: {},
					8084: {},
					8085: {},
					8086: {},
					8087: {},
					8088: {},
				}
				for _, v := range c.Scope.Ports {
					if _, ok := expected[v]; !ok {
						t.Errorf("failed to load ports")
					}
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConfig()

			// Create a temporary file and write the config data to it
			tmpfile, err := os.CreateTemp("", "config")
			if err != nil {
				t.Fatal(err)
			}

			// Obtain the absolute path of the file
			absPath, err := filepath.Abs(tmpfile.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(absPath) // clean up

			if _, err := tmpfile.Write(tt.args.cfg); err != nil {
				t.Fatal(err)
			}
			if err := tmpfile.Close(); err != nil {
				t.Fatal(err)
			}

			// Call LoadScopeSettings with the absolute file path
			err = c.LoadSettings(absPath)

			if (err != nil) != tt.wantErr {
				t.Errorf(" %v error = %v", tt.name, err)
			}

			tt.assertionFunc(t, c)
		})
	}
}
