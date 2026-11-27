// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// routeObject is one routing registry (IRR) route or route6 object: the
// prefix, the AS it says may originate it, its maintainers and the registry
// it is in.
type routeObject struct {
	prefix      netip.Prefix
	origin      int
	maintainers []string
	source      string
}

// roa is one RPKI Route Origin Authorization covering a prefix.
type roa struct {
	origin    int
	prefix    netip.Prefix
	maxLength int
	validity  string
}

// asNumber reads an AS number written as 3333, "3333" or "AS3333".
func asNumber(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		s := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(t)), "AS")
		n, err := strconv.Atoi(s)
		if err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// parseStatWhois reads the route objects of a RIPEstat whois answer: each
// irr_records entry is a list of key/value pairs.
func parseStatWhois(data []byte) ([]routeObject, error) {
	var resp struct {
		Data struct {
			IRRRecords [][]struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"irr_records"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("RIPEstat whois: %w", err)
	}

	var out []routeObject
	for _, rec := range resp.Data.IRRRecords {
		var o routeObject
		for _, kv := range rec {
			o.add(kv.Key, kv.Value)
		}
		if o.valid() {
			out = append(out, o)
		}
	}
	return out, nil
}

// add reads one attribute of a route object.
func (o *routeObject) add(key, value string) {
	value = strings.TrimSpace(value)
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "route", "route6":
		if p, err := netip.ParsePrefix(value); err == nil {
			o.prefix = p.Masked()
		}
	case "origin":
		o.origin = asNumber(value)
	case "mnt-by":
		for _, m := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' }) {
			if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
				o.maintainers = append(o.maintainers, m)
			}
		}
	case "source":
		o.source = strings.ToUpper(value)
	}
}

func (o routeObject) valid() bool {
	return o.prefix.IsValid() && o.origin > 0 && len(o.maintainers) > 0 && o.source != ""
}

// parseRPSL reads the route and route6 objects of a routing registry whois
// answer, in RPSL: objects separated by blank lines, one "key: value" per
// line, continuation lines starting with white space or '+'.
func parseRPSL(text string) []routeObject {
	var out []routeObject
	var o routeObject
	var route bool
	flush := func() {
		if route && o.valid() {
			out = append(out, o)
		}
		o, route = routeObject{}, false
	}

	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || line[0] == ' ' || line[0] == '\t' ||
			line[0] == '+' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if k := strings.ToLower(strings.TrimSpace(key)); k == "route" || k == "route6" {
			route = true
		}
		o.add(key, value)
	}
	flush()
	return out
}

// parseRPKIValidation reads a RIPEstat rpki-validation answer: the validity
// of the prefix and origin asked about, and the ROAs that cover the prefix.
func parseRPKIValidation(data []byte) (string, []roa, error) {
	var resp struct {
		Data struct {
			Status         string `json:"status"`
			ValidatingROAs []struct {
				Origin    any    `json:"origin"`
				Prefix    string `json:"prefix"`
				MaxLength int    `json:"max_length"`
				Validity  string `json:"validity"`
			} `json:"validating_roas"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", nil, fmt.Errorf("RIPEstat rpki-validation: %w", err)
	}

	var out []roa
	for _, r := range resp.Data.ValidatingROAs {
		p, err := netip.ParsePrefix(r.Prefix)
		n := asNumber(r.Origin)
		if err != nil || n == 0 {
			continue
		}
		out = append(out, roa{origin: n, prefix: p.Masked(), maxLength: r.MaxLength,
			validity: strings.ToLower(r.Validity)})
	}
	return strings.ToLower(resp.Data.Status), out, nil
}

// covers reports whether a ROA authorizes its origin to announce prefix: the
// ROA's prefix holds it and the prefix is no longer than the ROA's maximum
// length.
func (r roa) covers(prefix netip.Prefix) bool {
	maxLen := r.maxLength
	if maxLen == 0 {
		maxLen = r.prefix.Bits()
	}
	return r.prefix.Bits() <= prefix.Bits() && r.prefix.Contains(prefix.Addr()) && prefix.Bits() <= maxLen
}
