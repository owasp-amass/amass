// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"net"
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
