// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigLoadBruteForceSettings(t *testing.T) {
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
			name: "success - brute force enabled",
			args: args{cfg: []byte(`
options:
  brute_force:
    enabled: true
    wordlists: []`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				bruteForce, ok := c.Options["brute_force"].(map[string]interface{})
				if !ok {
					t.Errorf("BruteForce not found")
					return
				}
				enabled, ok := bruteForce["enabled"].(bool)
				if !ok || !enabled {
					t.Errorf("BruteForce not enabled")
				}
				wordlist, ok := bruteForce["wordlists"].([]interface{})
				if !ok || len(wordlist) != 0 {
					t.Errorf("Wordlist not correctly set")
				}
			},
		},
		{
			name: "failure - missing brute force settings",
			args: args{cfg: []byte(`
options:
  something_else:
    some_setting: true`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if _, ok := c.Options["brute_force"]; ok {
					t.Errorf("BruteForce should not be found")
				}
			},
		},
		{
			name: "success - brute force disabled",
			args: args{cfg: []byte(`
options:
  brute_force:
    enabled: false
    wordlists: []`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				bruteForce, ok := c.Options["brute_force"].(map[string]interface{})
				if !ok {
					t.Errorf("BruteForce not found")
					return
				}
				enabled, ok := bruteForce["enabled"].(bool)
				if !ok || enabled {
					t.Errorf("BruteForce should not be enabled")
				}
			},
		},
		{
			name: "failure - missing wordlist",
			args: args{cfg: []byte(`
options:
  brute_force:
    enabled: true`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				bruteForce, ok := c.Options["brute_force"].(map[string]interface{})
				if !ok {
					t.Errorf("BruteForce not found")
					return
				}
				_, ok = bruteForce["wordlists"].([]interface{})
				if ok {
					t.Errorf("Wordlist was found, but it is not in the YAML")
				}
			},
		},
		{
			name: "success - minimal wordlist",
			args: args{cfg: []byte(`
options:
  brute_force:
    enabled: true
    wordlists: 
      - "wordlist_file"`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				bruteForce, ok := c.Options["brute_force"].(map[string]interface{})
				if !ok {
					t.Errorf("BruteForce not found")
					return
				}
				wordlist, ok := bruteForce["wordlists"].([]interface{})
				if !ok || len(wordlist) != 1 {
					t.Errorf("Wordlist not correctly set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{}
			if err := yaml.Unmarshal(tt.args.cfg, c); (err != nil) != tt.wantErr {
				t.Errorf("yaml.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.assertionFunc(t, c)
		})
	}
}

func TestConfigLoadAlterationSettings(t *testing.T) {
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
			name: "success - check default for enabled",
			args: args{cfg: []byte(`
options:
  name_alteration:
    enabled: false
    wordlists: []
            `)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				nameAlteration, ok := c.Options["name_alteration"].(map[string]interface{})
				if !ok {
					t.Errorf("NameAlteration not found")
					return
				}
				enabled, ok := nameAlteration["enabled"].(bool)
				if !ok || enabled {
					t.Errorf("NameAlteration should not be enabled")
				}
			},
		},
		{
			name: "success - enabled, with wordlist file",
			args: args{cfg: []byte(`
options:
  name_alteration:
    enabled: true
    wordlists: 
      - "test_word"
            `)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				nameAlteration, ok := c.Options["name_alteration"].(map[string]interface{})
				if !ok {
					t.Errorf("NameAlteration not found")
					return
				}
				enabled, ok := nameAlteration["enabled"].(bool)
				if !ok || !enabled {
					t.Errorf("NameAlteration not enabled")
				}
				wordlist, ok := nameAlteration["wordlists"].([]interface{})
				if !ok || len(wordlist) != 1 {
					t.Errorf("Wordlist not correctly set")
				}
			},
		},
		{
			name: "failure - missing wordlist",
			args: args{cfg: []byte(`
options:
  name_alteration:
    enabled: true
            `)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				nameAlteration, ok := c.Options["name_alteration"].(map[string]interface{})
				if !ok {
					t.Errorf("NameAlteration not found")
					return
				}
				_, ok = nameAlteration["wordlists"].([]interface{})
				if ok {
					t.Errorf("Wordlist was found, but not in YAML")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{}
			if err := yaml.Unmarshal(tt.args.cfg, c); (err != nil) != tt.wantErr {
				t.Errorf("Config.loadAlterationSettings() error = %v, wantErr %v", err, tt.wantErr)
			}
			tt.assertionFunc(t, c)
		})
	}
}
