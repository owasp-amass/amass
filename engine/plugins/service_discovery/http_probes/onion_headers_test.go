// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

// TestNewOnionHeaders verifies that the constructor returns a valid Plugin
// with the correct name.
func TestNewOnionHeaders(t *testing.T) {
	p := NewOnionHeaders()
	if p == nil {
		t.Fatal("NewOnionHeaders() returned nil")
	}
	if _, ok := p.(et.Plugin); !ok {
		t.Fatal("NewOnionHeaders() does not implement et.Plugin")
	}
	if p.Name() != "Onion-Location-Headers" {
		t.Errorf("unexpected plugin name: got %q, want %q", p.Name(), "Onion-Location-Headers")
	}
}

// TestExtractOnionURL covers the core URL extraction and validation logic.
func TestExtractOnionURL(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantNil  bool
		wantHost string
		wantScheme string
	}{
		{
			name:       "valid https onion URL",
			input:      "https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
			wantNil:    false,
			wantHost:   "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
			wantScheme: "https",
		},
		{
			name:       "valid http onion URL",
			input:      "http://facebookwkhpilnemxj7ascrwwwi72yxv7r2hidjleco5ibivzknjgid.onion",
			wantNil:    false,
			wantHost:   "facebookwkhpilnemxj7ascrwwwi72yxv7r2hidjleco5ibivzknjgid.onion",
			wantScheme: "http",
		},
		{
			name:       "onion URL with path",
			input:      "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/search?q=test",
			wantNil:    false,
			wantHost:   "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
			wantScheme: "https",
		},
		{
			name:      "missing scheme defaults to https",
			input:     "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
			wantNil:   false,
			wantHost:  "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
			wantScheme: "https",
		},
		{
			name:    "non-onion URL is rejected",
			input:   "https://example.com",
			wantNil: true,
		},
		{
			name:    "empty string is rejected",
			input:   "",
			wantNil: true,
		},
		{
			name:    "whitespace-only string is rejected",
			input:   "   ",
			wantNil: true,
		},
		{
			name:    "plain hostname without onion suffix is rejected",
			input:   "https://notanonion.net",
			wantNil: true,
		},
		{
			name:    "onion in path but not host is rejected",
			input:   "https://example.com/path/to/.onion",
			wantNil: true,
		},
		{
			name:      "uppercase ONION suffix is accepted",
			input:     "https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.ONION",
			wantNil:   false,
			wantHost:  "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
			wantScheme: "https",
		},
		{
			name:      "leading and trailing whitespace is stripped",
			input:     "  https://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion  ",
			wantNil:   false,
			wantHost:  "protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
			wantScheme: "https",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractOnionURL(tc.input)

			if tc.wantNil {
				if got != nil {
					t.Errorf("expected nil for input %q, got %+v", tc.input, got)
				}
				return
			}

			if got == nil {
				t.Fatalf("expected non-nil URL for input %q, got nil", tc.input)
			}
			if got.Host != tc.wantHost {
				t.Errorf("Host: got %q, want %q", got.Host, tc.wantHost)
			}
			if got.Scheme != tc.wantScheme {
				t.Errorf("Scheme: got %q, want %q", got.Scheme, tc.wantScheme)
			}
			if got.Raw == "" {
				t.Error("Raw URL should not be empty")
			}
		})
	}
}
