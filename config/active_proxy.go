// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// supportedActiveProxySchemes lists the URL schemes the engine currently
// recognises for the ActiveProxy egress profile.
var supportedActiveProxySchemes = map[string]struct{}{
	"http":    {},
	"https":   {},
	"socks5":  {},
	"socks5h": {},
}

// validateActiveProxyURL checks that the operator-supplied active proxy URL
// is structurally a usable upstream proxy. It does NOT dial the proxy.
func validateActiveProxyURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("active_proxy is empty")
	}

	// url.Parse is permissive: "127.0.0.1:8080" parses without error but
	// produces an empty Scheme. Detect the missing-scheme case before
	// calling Parse so the error message always mentions "scheme".
	if !strings.Contains(raw, "://") {
		return fmt.Errorf("active_proxy must include a scheme (http, https, socks5, socks5h)")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("active_proxy is not a valid URL: %w", err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("active_proxy must include a scheme (http, https, socks5, socks5h)")
	}
	if u.Host == "" {
		return fmt.Errorf("active_proxy must include a host:port")
	}
	scheme := strings.ToLower(u.Scheme)
	if _, ok := supportedActiveProxySchemes[scheme]; !ok {
		return fmt.Errorf("active_proxy scheme %q is not supported (use http, https, socks5, socks5h)", u.Scheme)
	}
	return nil
}

// loadActiveProxySettings reads the active_proxy and active_strict options
// from the YAML Options map. Operators who set them via -active-proxy on the
// CLI will already have them populated by OverrideConfig; this loader simply
// supports the YAML form.
func (c *Config) loadActiveProxySettings(cfg *Config) error {
	if v, ok := c.Options["active_proxy"]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("failed to parse active_proxy setting, value is not a string")
		}
		c.ActiveProxy = strings.TrimSpace(s)
	}

	if v, ok := c.Options["active_strict"]; ok {
		b, ok := v.(bool)
		if !ok {
			return fmt.Errorf("failed to parse active_strict setting, value is not a boolean")
		}
		c.ActiveStrict = b
	}

	if v, ok := c.Options["active_dns_resolver"]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("failed to parse active_dns_resolver setting, value is not a string")
		}
		c.ActiveDNSResolver = strings.TrimSpace(s)
	}
	return nil
}

// UnmarshalJSON ensures the active egress defaults match what CLI operators
// get from NewConfig when a direct API caller omits the active_strict field.
// Without this, json.Unmarshal would zero-value ActiveStrict to false and
// silently weaken the engine's fail-closed posture for API callers.
//
// The intended default is true: if "active_strict" is absent in the JSON
// payload, ActiveStrict is set to true; if the caller explicitly sends
// "active_strict": false, that value is honored.
func (c *Config) UnmarshalJSON(data []byte) error {
	type configAlias Config
	aux := struct {
		ActiveStrict *bool `json:"active_strict,omitempty"`
		*configAlias
	}{
		configAlias: (*configAlias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.ActiveStrict != nil {
		c.ActiveStrict = *aux.ActiveStrict
	} else {
		c.ActiveStrict = true
	}
	return nil
}
