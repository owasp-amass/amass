// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package reversesearch holds the pure, network-free helpers shared by the
// origin-IP reverse-search collectors (Shodan, Censys, FOFA, ZoomEye): building
// each source's search query from a fingerprint Identifier, and parsing each
// source's JSON response into origin hits. The plugins own the HTTP client,
// authentication and storage; everything here is deterministic and unit-tested
// against recorded sample responses, so it can be built and verified before any
// API key or network is in play. The query syntax and response shapes are the
// published ones as of this writing and must be re-confirmed against a live
// response during validation (reverse-search-collectors-spec.md).
package reversesearch

import (
	"encoding/base64"
	"encoding/json"
	"strconv"

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
)

// jarmIDType is the id_type the JARM plugin stores (a literal, not an
// internal/fingerprint constant).
const jarmIDType = "JARM"

// faviconMD5IDType is the favicon hash Censys indexes (MD5), distinct from the
// mmh3 favicon Shodan/FOFA/ZoomEye use. Amass does not store it yet; the Censys
// query builder accepts it so the collector works once it is collected.
const faviconMD5IDType = "favicon_md5"

// Hit is one host a reverse-search source reports as serving a fingerprint. Port
// is 0 when the source does not report one.
type Hit struct {
	IP   string
	Port int
}

// ShodanQuery builds a Shodan search query for a fingerprint, or ok=false when
// Shodan cannot key on that id_type. Shodan indexes the mmh3 favicon hash and
// the JARM.
func ShodanQuery(idType, value string) (string, bool) {
	switch idType {
	case fingerprint.FaviconMMH3:
		return "http.favicon.hash:" + value, true
	case jarmIDType:
		return "ssl.jarm:" + value, true
	}

	return "", false
}

// FofaQuery builds a FOFA query string for a fingerprint (before base-64
// encoding), or ok=false when FOFA cannot key on that id_type.
func FofaQuery(idType, value string) (string, bool) {
	switch idType {
	case fingerprint.FaviconMMH3:
		return `icon_hash="` + value + `"`, true
	case jarmIDType:
		return `jarm="` + value + `"`, true
	}

	return "", false
}

// FofaQueryBase64 builds a FOFA query and returns it base-64 encoded, as the
// FOFA API's qbase64 parameter expects.
func FofaQueryBase64(idType, value string) (string, bool) {
	q, ok := FofaQuery(idType, value)
	if !ok {
		return "", false
	}

	return base64.StdEncoding.EncodeToString([]byte(q)), true
}

// ZoomEyeQuery builds a ZoomEye search query for a fingerprint, or ok=false when
// ZoomEye cannot key on that id_type.
func ZoomEyeQuery(idType, value string) (string, bool) {
	switch idType {
	case fingerprint.FaviconMMH3:
		return `iconhash:"` + value + `"`, true
	case jarmIDType:
		return `jarm:"` + value + `"`, true
	}

	return "", false
}

// CensysQuery builds a Censys hosts-search query for a fingerprint, or ok=false
// when Censys cannot key on that id_type. Censys indexes the JARM and the MD5
// favicon hash; it does not index the mmh3 favicon Amass stores today.
func CensysQuery(idType, value string) (string, bool) {
	switch idType {
	case jarmIDType:
		return `services.jarm.fingerprint:"` + value + `"`, true
	case faviconMD5IDType:
		return `services.http.response.favicons.md5_hash:"` + value + `"`, true
	}

	return "", false
}

// ParseShodan parses a Shodan /shodan/host/search response into origin hits.
func ParseShodan(data []byte) ([]Hit, error) {
	var r struct {
		Matches []struct {
			IPStr string `json:"ip_str"`
			Port  int    `json:"port"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	var hits []Hit
	for _, m := range r.Matches {
		hits = append(hits, Hit{IP: m.IPStr, Port: m.Port})
	}

	return dedup(hits), nil
}

// ParseCensys parses a Censys v2 /hosts/search response into origin hits, one
// per host service (or one with no port when the host lists none).
func ParseCensys(data []byte) ([]Hit, error) {
	var r struct {
		Result struct {
			Hits []struct {
				IP       string `json:"ip"`
				Services []struct {
					Port int `json:"port"`
				} `json:"services"`
			} `json:"hits"`
		} `json:"result"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	var hits []Hit
	for _, h := range r.Result.Hits {
		if len(h.Services) == 0 {
			hits = append(hits, Hit{IP: h.IP})
			continue
		}
		for _, s := range h.Services {
			hits = append(hits, Hit{IP: h.IP, Port: s.Port})
		}
	}

	return dedup(hits), nil
}

// ParseFofa parses a FOFA /search/all response into origin hits. The collector
// requests fields=ip,port, so each result row is [ip, port].
func ParseFofa(data []byte) ([]Hit, error) {
	var r struct {
		Error   bool       `json:"error"`
		Errmsg  string     `json:"errmsg"`
		Results [][]string `json:"results"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	var hits []Hit
	for _, row := range r.Results {
		if len(row) == 0 || row[0] == "" {
			continue
		}
		h := Hit{IP: row[0]}
		if len(row) > 1 {
			if p, err := strconv.Atoi(row[1]); err == nil {
				h.Port = p
			}
		}
		hits = append(hits, h)
	}

	return dedup(hits), nil
}

// ParseZoomEye parses a ZoomEye /host/search response into origin hits.
func ParseZoomEye(data []byte) ([]Hit, error) {
	var r struct {
		Matches []struct {
			IP       string `json:"ip"`
			PortInfo struct {
				Port int `json:"port"`
			} `json:"portinfo"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	var hits []Hit
	for _, m := range r.Matches {
		hits = append(hits, Hit{IP: m.IP, Port: m.PortInfo.Port})
	}

	return dedup(hits), nil
}

// dedup removes repeated ip:port hits and drops entries with no IP, preserving
// order.
func dedup(in []Hit) []Hit {
	seen := map[string]bool{}
	out := make([]Hit, 0, len(in))
	for _, h := range in {
		if h.IP == "" {
			continue
		}
		key := h.IP + ":" + strconv.Itoa(h.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}

	return out
}
