// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/go-ini/ini"
)

func TestConfigloadBruteForceSettings(t *testing.T) {
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
			name: "success - all sans wordlist",
			args: args{cfg: []byte(`
			[bruteforce]
			enabled = true
			recursive = true
			minimum_for_recursive = 1
			#wordlist_file = /dev/null
			#wordlist_file = /dev/null
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if !c.Recursive {
					t.Errorf("Config.loadBruteForceSettings() error = %v", "Recursive not set")
				}
				if c.MinForRecursive != 1 {
					t.Errorf("Config.loadBruteForceSettings() error = %v", "MinForRecursive not equal")
				}
			},
		},
		{
			name: "failure - missing section",
			args: args{cfg: []byte(`
			[missing-bruteforce]
			sample-setting: true
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if c.Recursive {
					t.Errorf("Config.loadBruteForceSettings() error = %v", "Recursive set")
				}
			},
		},
		{
			name: "sucess - not enabled",
			args: args{cfg: []byte(`
			[bruteforce]
			enabled = false
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "failure - missing wordlist",
			args: args{cfg: []byte(`
			[bruteforce]
			enabled = true
			wordlist_file = ./nonexistant_file
			`)},
			wantErr: true,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "sucess - minimal wordlist",
			args: args{cfg: []byte(`
			[bruteforce]
			enabled = true
			wordlist_file = ./test_wordlist.txt
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
				t.Errorf("Config.loadBruteForceSettings() error = %v", err)
			}

			if err := c.loadBruteForceSettings(iniFile); (err != nil) != tt.wantErr {
				t.Errorf("Config.loadBruteForceSettings() error = %v, wantErr %v", err, tt.wantErr)
			}

			tt.assertionFunc(t, c)

		})

	}
}

func TestConfigloadAlterationSettings(t *testing.T) {
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
			[alterations]
			enabled: false
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
				if c.Alterations {
					t.Errorf("Config.loadAlterationSettings(): default for alterations changed")
				}
			},
		},
		{
			name: "success - enabled, with wordlist file",
			args: args{cfg: []byte(`
			[alterations]
			enabled: true
			wordlist_file: ./test_wordlist.txt
			`)},
			wantErr: false,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
		{
			name: "success - enabled",
			args: args{cfg: []byte(`
			[alterations]
			enabled: true
			wordlist_file: ./nonexistant_file
			`)},
			wantErr: true,
			assertionFunc: func(t *testing.T, c *Config) {
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := new(Config)
			iniFile, err := ini.Load(tt.args.cfg)
			if err != nil {
				t.Errorf("Config.loadAlterationSettings() error = %v", err)
			}

			if err := c.loadAlterationSettings(iniFile); (err != nil) != tt.wantErr {
				t.Errorf("Config.loadAlterationSettings() error = %v, wantErr %v", err, tt.wantErr)
			}

			tt.assertionFunc(t, c)
		})
	}
}
