// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateActiveProxyURL(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantErr  bool
		errMatch string
	}{
		{"empty", "", true, "empty"},
		{"missing scheme", "127.0.0.1:8080", true, "scheme"},
		{"no host", "http://", true, "host"},
		{"unsupported scheme", "ftp://proxy.example:8080", true, "not supported"},
		{"http ok", "http://proxy.example:8080", false, ""},
		{"socks5 ok", "socks5://10.0.0.1:1080", false, ""},
		{"socks5h ok", "socks5h://10.0.0.1:1080", false, ""},
		{"https ok with auth", "https://user:pass@proxy.example:443", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateActiveProxyURL(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && tc.errMatch != "" && !strings.Contains(err.Error(), tc.errMatch) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.errMatch)
			}
		})
	}
}

func TestCheckSettings_ActiveProxyEnforcement(t *testing.T) {
	t.Run("active + no proxy + strict => error", func(t *testing.T) {
		c := NewConfig()
		c.Active = true
		// NewConfig sets ActiveStrict=true; do not override.
		if err := c.CheckSettings(); err == nil ||
			!strings.Contains(err.Error(), "active_proxy") {
			t.Fatalf("expected fail-closed error mentioning active_proxy, got: %v", err)
		}
	})

	t.Run("active + proxy + strict => ok", func(t *testing.T) {
		c := NewConfig()
		c.Active = true
		c.ActiveProxy = "socks5://127.0.0.1:1080"
		if err := c.CheckSettings(); err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	})

	t.Run("active + no proxy + non-strict => ok", func(t *testing.T) {
		c := NewConfig()
		c.Active = true
		c.ActiveStrict = false
		if err := c.CheckSettings(); err != nil {
			t.Fatalf("expected no error with strict off, got: %v", err)
		}
	})

	t.Run("active + invalid proxy URL => error", func(t *testing.T) {
		c := NewConfig()
		c.Active = true
		c.ActiveProxy = "not a url"
		if err := c.CheckSettings(); err == nil {
			t.Fatalf("expected error for invalid proxy URL")
		}
	})

	t.Run("passive run with strict default => ok", func(t *testing.T) {
		c := NewConfig()
		c.Active = false
		if err := c.CheckSettings(); err != nil {
			t.Fatalf("strict default should not affect non-active runs, got: %v", err)
		}
	})
}

func TestLoadActiveProxySettings(t *testing.T) {
	c := NewConfig()
	c.Options["active_proxy"] = "http://10.0.0.1:3128"
	c.Options["active_strict"] = false

	if err := c.loadActiveProxySettings(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ActiveProxy != "http://10.0.0.1:3128" {
		t.Errorf("ActiveProxy not loaded, got %q", c.ActiveProxy)
	}
	if c.ActiveStrict != false {
		t.Errorf("ActiveStrict not loaded from options, got %v", c.ActiveStrict)
	}

	t.Run("non-string active_proxy", func(t *testing.T) {
		c := NewConfig()
		c.Options["active_proxy"] = 42
		if err := c.loadActiveProxySettings(c); err == nil {
			t.Fatalf("expected error for non-string active_proxy")
		}
	})

	t.Run("non-bool active_strict", func(t *testing.T) {
		c := NewConfig()
		c.Options["active_strict"] = "yes"
		if err := c.loadActiveProxySettings(c); err == nil {
			t.Fatalf("expected error for non-bool active_strict")
		}
	})
}

func TestActiveFieldsJSONMarshal(t *testing.T) {
	c := NewConfig()
	c.Active = true
	c.ActiveProxy = "socks5://10.0.0.1:1080"
	c.ActiveStrict = true
	c.ActiveDNSResolver = "10.0.0.1:53"

	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	s := string(raw)
	for _, want := range []string{
		`"active":true`,
		`"active_proxy":"socks5://10.0.0.1:1080"`,
		`"active_strict":true`,
		`"active_dns_resolver":"10.0.0.1:53"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("marshaled JSON missing %s: %s", want, s)
		}
	}
}

func TestActiveFieldsJSONUnmarshal(t *testing.T) {
	t.Run("all active fields present", func(t *testing.T) {
		payload := []byte(`{
            "active": true,
            "active_proxy": "http://proxy.example:3128",
            "active_strict": false,
            "active_dns_resolver": "10.0.0.1:53"
        }`)
		var c Config
		if err := json.Unmarshal(payload, &c); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if !c.Active {
			t.Errorf("Active not set from JSON")
		}
		if c.ActiveProxy != "http://proxy.example:3128" {
			t.Errorf("ActiveProxy = %q, want %q", c.ActiveProxy, "http://proxy.example:3128")
		}
		if c.ActiveStrict != false {
			t.Errorf("ActiveStrict = %v, want false (explicit override)", c.ActiveStrict)
		}
		if c.ActiveDNSResolver != "10.0.0.1:53" {
			t.Errorf("ActiveDNSResolver = %q, want %q", c.ActiveDNSResolver, "10.0.0.1:53")
		}
	})

	t.Run("active_strict absent defaults to true", func(t *testing.T) {
		payload := []byte(`{
            "active": true,
            "active_proxy": "http://proxy.example:3128"
        }`)
		var c Config
		if err := json.Unmarshal(payload, &c); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if !c.ActiveStrict {
			t.Errorf("ActiveStrict should default to true when omitted from JSON, got false")
		}
	})

	t.Run("active_strict explicit true honored", func(t *testing.T) {
		payload := []byte(`{"active_strict": true}`)
		var c Config
		if err := json.Unmarshal(payload, &c); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if !c.ActiveStrict {
			t.Errorf("explicit active_strict=true not honored")
		}
	})

	t.Run("active_strict explicit false honored", func(t *testing.T) {
		payload := []byte(`{"active_strict": false}`)
		var c Config
		if err := json.Unmarshal(payload, &c); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if c.ActiveStrict {
			t.Errorf("explicit active_strict=false not honored, ActiveStrict still true")
		}
	})

	t.Run("empty JSON object defaults strict to true", func(t *testing.T) {
		var c Config
		if err := json.Unmarshal([]byte(`{}`), &c); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}
		if !c.ActiveStrict {
			t.Errorf("ActiveStrict should default to true on empty JSON, got false")
		}
	})
}

// TestActiveFieldsRoundTrip ensures that a CLI-style Config marshaled to JSON
// and unmarshaled back yields the same active egress settings, the path that
// applies when the enum container forwards its config to the engine container.
func TestActiveFieldsRoundTrip(t *testing.T) {
	src := NewConfig()
	src.Active = true
	src.ActiveProxy = "socks5h://10.0.0.1:1080"
	src.ActiveStrict = true
	src.ActiveDNSResolver = "10.0.0.1:53"

	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var dst Config
	if err := json.Unmarshal(raw, &dst); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if dst.Active != src.Active ||
		dst.ActiveProxy != src.ActiveProxy ||
		dst.ActiveStrict != src.ActiveStrict ||
		dst.ActiveDNSResolver != src.ActiveDNSResolver {
		t.Fatalf("round trip mismatch: src=%+v dst.Active=%v dst.ActiveProxy=%q dst.ActiveStrict=%v dst.ActiveDNSResolver=%q",
			src, dst.Active, dst.ActiveProxy, dst.ActiveStrict, dst.ActiveDNSResolver)
	}
}

// TestCheckSettings_APIPayloadStrictDefault exercises the exact flow the
// engine API handler uses: unmarshal a JSON payload that lacks active_strict
// then run CheckSettings. With Active=true and no proxy provided, this MUST
// fail closed even though the caller did not explicitly send active_strict.
func TestCheckSettings_APIPayloadStrictDefault(t *testing.T) {
	payload := []byte(`{"active": true}`)
	var c Config
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if err := c.CheckSettings(); err == nil ||
		!strings.Contains(err.Error(), "active_proxy") {
		t.Fatalf("expected fail-closed error mentioning active_proxy when API payload omits active_strict, got: %v", err)
	}
}
