// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"testing"

	"github.com/go-ini/ini"
	"github.com/stretchr/testify/assert"
)

func TestConfig_loadBruteForceSettings(t *testing.T) {
	type args struct {
		cfg []byte
	}

	tests := []struct {
		name          string
		args          args
		wantErr       assert.ErrorAssertionFunc
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
			wantErr: assert.NoError,
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
			wantErr: assert.NoError,
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

			assert.NoError(t, err, "Config.loadBruteForceSettings() error = %v", err)
			tt.wantErr(t, c.loadBruteForceSettings(iniFile))
			tt.assertionFunc(t, c)

		})

	}
}
