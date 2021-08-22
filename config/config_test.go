// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"net"
	"reflect"
	"sort"
	"testing"
)

func TestCheckSettings(t *testing.T) {
	c := NewConfig()

	err := c.CheckSettings()

	if err != nil {
		t.Errorf("Error checking settings.\n%v", err)
	}

}
func TestDomainRegex(t *testing.T) {
	c := NewConfig()
	got := c.DomainRegex("owasp.org")

	if got != nil {
		t.Errorf("Error with DomainRegex.\n%v", got)
	}
}

func TestAddDomains(t *testing.T) {
	c := NewConfig()
	example := "owasp.org/test"
	list := []string{"owasp.org", "google.com", "yahoo.com"}
	c.AddDomains(list...)
	got := c.Domains()
	sort.Strings(list)
	sort.Strings(got)
	c.AddDomains(list...)

	if !reflect.DeepEqual(list, got) {
		t.Errorf("Domains do not match.\nWanted:%v\nGot:%v\n", list, got)
	}
	t.Run("Testing AddDomain...", func(t *testing.T) {

		c.AddDomain(example)
		want := true
		got := false
		for _, l := range c.domains {
			if example == l {
				got = true
			}
		}
		if got != want {
			t.Errorf("Expected:%v\nGot:%v", want, got)
		}
		t.Run("Testing Domains...", func(t *testing.T) {
			if c.Domains() == nil {
				t.Errorf("No domains in current configuration.")
			}

			if len(c.Domains()) <= 0 {
				t.Errorf("Failed to populate c.domains.\nLength:%v", len(c.Domains()))
			}

		})

		t.Run("Testing IsDomainInScope...", func(t *testing.T) {

			if !c.IsDomainInScope(example) {
				t.Errorf("Domain is considered out of scope.\nExample:%v\nGot:%v,\nWant:%v", example, got, want)
			}
		})

		t.Run("Testing WhichDomain...", func(t *testing.T) {

			if example != c.WhichDomain(example) {
				t.Errorf("Failed to find example.\nExample:%v\nGot:%v", example, got)
			}
		})
	})
}

func TestIsAddressInScope(t *testing.T) {
	c := NewConfig()
	example := "10.10.0.1"
	c.Addresses = append(c.Addresses, net.ParseIP(example))
	if !c.IsAddressInScope(example) {
		t.Errorf("Failed to find address %v in scope.\nAddress List:%v", example, c.Addresses)
	}
}

func TestBlacklist(t *testing.T) {
	c := NewConfig()
	example := "owasp.org"
	c.Blacklist = append(c.Blacklist, example)
	got := c.Blacklisted(example)
	want := true

	if got != want {
		t.Errorf("Failed to find %v in blacklist.", example)
	}
}

func TestLoadSettings(t *testing.T) {
	c := NewConfig()
	path := "../examples/config.ini"
	if c.LoadSettings(path) != nil {
		t.Errorf("Config file failed to load.")
	}
}

func TestConfig_CheckSettings(t *testing.T) {
	type fields struct {
		c *Config
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "brute-force & passive set",
			fields: fields{
				&Config{BruteForcing: true, Passive: true},
			},
			wantErr: true,
		},
		{
			name: "brute-force & empty wordlist - load default wordlist",
			fields: fields{
				&Config{BruteForcing: true, Passive: false, Wordlist: []string{}},
			},
			wantErr: false,
		},
		{
			name: "active & passive enumeration set",
			fields: fields{
				&Config{Passive: true, Active: true},
			},
			wantErr: true,
		},
		{
			name: "alterations set with empty alt-wordlist - load default alt-wordlist",
			fields: fields{
				&Config{Alterations: true, AltWordlist: []string{}},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fields.c.CheckSettings(); (err != nil) != tt.wantErr {
				t.Errorf("Config.CheckSettings() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetListFromFile(t *testing.T) {
	var list = "../examples/wordlists/deepmagic.com_top500prefixes.txt"
	if _, err := GetListFromFile(list); err != nil {
		t.Errorf("GetListFromFile() error = %v", err)
	}
}
