// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
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
		for _, l := range c.Scope.Domains {
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
	var ipNet ParseIPs

	// Example string to use to convert the appropriate data type and populate c.Scope.IP
	example := "192.0.2.1"
	_ = ipNet.parseRange(example)
	c.Scope.Addresses = ipNet

	c.Scope.IP = append(c.Scope.IP, string(c.Scope.Addresses[0]))
	if !c.IsAddressInScope(example) {
		t.Errorf("Failed to find address %v in scope.\nAddress List:%v", example, c.Scope.Addresses)
	}
}

func TestBlacklist(t *testing.T) {
	c := NewConfig()
	example := "owasp.org"
	c.Scope.Blacklist = append(c.Scope.Blacklist, example)
	got := c.Blacklisted(example)
	want := true

	if got != want {
		t.Errorf("Failed to find %v in blacklist.", example)
	}
}

func TestConfigCheckSettings(t *testing.T) {
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

var configyaml = []byte(`
options:
   database: "postgres://postgres:testPasWORD123456!)*&*$@localhost:5432"
`)

func TestMarshalJSON(t *testing.T) {
	c := NewConfig()

	// Test case 1: MarshalJSON returns the expected JSON bytes
	t.Run("MarshalJSON returns the expected JSON bytes", func(t *testing.T) {
		expected := []byte(`{"seed":{},"scope":{"ports":[80,443]},"rigid_boundaries":false,"resolvers":null,"datasource_config":{},"transformations":{}}
`)
		got, err := c.JSON()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("Unexpected JSON bytes.\nExpected: %s\nGot: %s", expected, got)
		}
	})

	if err := yaml.Unmarshal(configyaml, c); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if err := c.loadDatabaseSettings(c); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// Test case 2: MarshalJSON unescapes HTML entities in the JSON bytes
	t.Run("MarshalJSON unescapes HTML entities in the JSON bytes", func(t *testing.T) {
		expected := []byte(`{"seed":{},"scope":{"ports":[80,443]},"database":[{"system":"postgres","primary":true,"url":"postgres://postgres:testPasWORD123456!)*&*$@localhost:5432","username":"postgres","password":"testPasWORD123456!)*&*$","host":"localhost","port":"5432"}],"rigid_boundaries":false,"resolvers":null,"datasource_config":{},"transformations":{}}
`)
		expectedString := string(expected)
		got, err := c.JSON()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		gotString := string(got)
		if !reflect.DeepEqual(got, expected) {
			t.Errorf("Unexpected JSON bytes.\nExpected: %s\nGot: %s", expected, got)
		}
		if gotString != expectedString {
			t.Errorf("Unexpected JSON string.\nExpected: %s\nGot: %s", expectedString, gotString)
		}
	})
}
