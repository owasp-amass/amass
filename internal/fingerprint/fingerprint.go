// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package fingerprint extracts the fingerprints Amass records for
// correlating assets: page titles, analytics and tag identifiers, page
// content hashes, favicon hashes, and names the SSH host key property. Every collector (the HTTP probes, a web
// scraper) calls this package and stores each fingerprint as an OAM
// SimpleProperty named Name with the value Value, so the stored data is the
// same whichever component collected it.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"html"
	"regexp"
	"strings"
)

// Property names: the storage contract with the ownership signals.
const (
	// Title is a page's trimmed <title>.
	Title = "http_title"
	// AnalyticsID is an analytics or tag-manager identifier on a page, with
	// a provider prefix where the identifier has none (fb-pixel:123).
	AnalyticsID = "analytics_id"
	// BodySHA256 is the hex SHA-256 of a page's normalized body.
	BodySHA256 = "body_sha256"
	// FaviconMMH3 is a favicon's MurmurHash3 in Shodan's convention, as a
	// signed decimal.
	FaviconMMH3 = "favicon_mmh3"
	// SSHHostKey is an SSH server's host key as "<key type>
	// SHA256:<base64 fingerprint>", as OpenSSH prints it.
	SSHHostKey = "ssh_host_key"
)

// Bounds.
const (
	// MinBodyBytes is the smallest normalized body that is hashed; shorter
	// bodies are redirects, error stubs and default pages.
	MinBodyBytes = 512
	maxTitle     = 200
	maxScan      = 2 << 20
)

// Fingerprint is one value to store.
type Fingerprint struct {
	Name  string
	Value string
}

var (
	titleTag = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	spaces   = regexp.MustCompile(`\s+`)
	// analytics are the identifier patterns: each match's first group is the
	// identifier, prefixed by the pattern's prefix.
	analytics = []struct {
		prefix string
		re     *regexp.Regexp
	}{
		{"", regexp.MustCompile(`\b(UA-\d{4,10}-\d{1,4})\b`)},
		{"", regexp.MustCompile(`\b(GTM-[A-Z0-9]{4,9})\b`)},
		{"", regexp.MustCompile(`googletagmanager\.com/gtag/js\?id=(G-[A-Z0-9]{6,12})`)},
		{"", regexp.MustCompile(`gtag\(\s*['"]config['"]\s*,\s*['"]((?:G|AW|DC)-[A-Z0-9]{6,12})['"]`)},
		{"", regexp.MustCompile(`\b(ca-pub-\d{10,20})\b`)},
		{"fb-pixel:", regexp.MustCompile(`fbq\(\s*['"]init['"]\s*,\s*['"](\d{10,20})['"]`)},
		{"hotjar:", regexp.MustCompile(`\bhjid\s*:\s*(\d{5,10})\b`)},
		{"clarity:", regexp.MustCompile(`clarity\.ms/tag/([a-z0-9]{8,12})\b`)},
	}
)

// FromHTTP returns the fingerprints of one HTTP response body: its title,
// its analytics identifiers and the hash of its normalized body. Headers are
// not used yet; they are taken so collectors need not change when they are.
func FromHTTP(_ map[string][]string, body string) []Fingerprint {
	if len(body) > maxScan {
		body = body[:maxScan]
	}

	var out []Fingerprint
	if t := PageTitle(body); t != "" {
		out = append(out, Fingerprint{Name: Title, Value: t})
	}
	for _, id := range AnalyticsIDs(body) {
		out = append(out, Fingerprint{Name: AnalyticsID, Value: id})
	}
	if h := BodyHash(body); h != "" {
		out = append(out, Fingerprint{Name: BodySHA256, Value: h})
	}

	return out
}

// PageTitle returns a page's title, unescaped, with whitespace collapsed,
// or "".
func PageTitle(body string) string {
	m := titleTag.FindStringSubmatch(body)
	if m == nil {
		return ""
	}

	t := strings.TrimSpace(spaces.ReplaceAllString(html.UnescapeString(m[1]), " "))
	if len(t) > maxTitle {
		t = strings.TrimSpace(t[:maxTitle])
	}

	return t
}

// AnalyticsIDs returns the distinct analytics and tag identifiers in a page,
// in the order found.
func AnalyticsIDs(body string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range analytics {
		for _, m := range a.re.FindAllStringSubmatch(body, -1) {
			if id := a.prefix + m[1]; !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}

	return out
}

// BodyHash returns the hex SHA-256 of a body with line endings normalized
// and surrounding whitespace trimmed, or "" for bodies shorter than
// MinBodyBytes.
func BodyHash(body string) string {
	b := strings.TrimSpace(strings.ReplaceAll(body, "\r\n", "\n"))
	if len(b) < MinBodyBytes {
		return ""
	}

	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:])
}
