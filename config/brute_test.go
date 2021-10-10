// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

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
