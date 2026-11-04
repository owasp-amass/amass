// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"bytes"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

// TestWarnUnsupportedConfig pins the warning emitted for the v5 wordlist
// brute-force gap reported in https://github.com/owasp-amass/amass/issues/1122.
func TestWarnUnsupportedConfig(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.Config
		wantWarning bool
	}{
		{
			name:        "nil config does nothing",
			cfg:         nil,
			wantWarning: false,
		},
		{
			name:        "no brute, no wordlist",
			cfg:         &config.Config{},
			wantWarning: false,
		},
		{
			name: "brute toggled on but no wordlist supplied",
			cfg: &config.Config{
				BruteForcing: true,
			},
			wantWarning: false,
		},
		{
			name: "wordlist supplied but brute disabled",
			cfg: &config.Config{
				Wordlist: []string{"foo", "bar"},
			},
			wantWarning: false,
		},
		{
			name: "brute on with wordlist - warns",
			cfg: &config.Config{
				BruteForcing: true,
				Wordlist:     []string{"foo", "bar"},
			},
			wantWarning: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			warnUnsupportedConfig(tc.cfg, &buf)
			out := buf.String()

			if tc.wantWarning {
				if !strings.Contains(out, "wordlist brute forcing") {
					t.Errorf("expected wordlist brute-force warning, got %q", out)
				}
				if !strings.Contains(out, "issues/1122") {
					t.Errorf("expected warning to reference issue #1122, got %q", out)
				}
			} else if out != "" {
				t.Errorf("expected no warning, got %q", out)
			}
		})
	}
}
