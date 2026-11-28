// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package secretscan recognizes credentials and cloud identifiers in text
// Amass collects, from their providers' public formats
// (internal/semantics/secret_patterns.json). A secret's value never leaves
// this package's results: callers store its kind, hash and masked preview,
// and Mask hides it in text sent to models. Found credentials are never used
// or tested.
package secretscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Find is one credential or identifier in a text.
type Find struct {
	Kind  string // the pattern's kind
	Title string
	// IDType is set when the find is an identifier (an AWS access key ID or
	// account ID), stored in full; otherwise it is a secret.
	IDType string
	// Value is the matched text. For a secret it must never be stored,
	// logged or sent anywhere: use Hash and Preview.
	Value      string
	Hash       string // SHA-256 of Value, hex
	Preview    string // Value masked
	Start, End int    // Value's position in the text
}

// Secret reports whether the find is a secret rather than an identifier.
func (f Find) Secret() bool { return f.IDType == "" }

type pattern struct {
	Kind       string  `json:"kind"`
	Title      string  `json:"title"`
	Pattern    string  `json:"pattern"`
	Group      int     `json:"group"`
	IDType     string  `json:"id_type,omitempty"`
	MinEntropy float64 `json:"min_entropy,omitempty"`
	Source     string  `json:"source"`
	re         *regexp.Regexp
}

type catalog struct {
	License          string    `json:"_license"`
	About            string    `json:"_about"`
	Patterns         []pattern `json:"patterns"`
	IgnoreValues     []string  `json:"ignore_values"`
	IgnoreSubstrings []string  `json:"ignore_substrings"`
}

var loadCatalog = sync.OnceValue(func() catalog {
	var c catalog
	dec := json.NewDecoder(bytes.NewReader(semantics.File("secret_patterns.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("secret_patterns.json: " + err.Error())
	}
	for i := range c.Patterns {
		p := &c.Patterns[i]
		p.re = regexp.MustCompile(p.Pattern)
		if p.Kind == "" || p.Title == "" || !strings.HasPrefix(p.Source, "https://") || p.Group < 1 ||
			p.Group > p.re.NumSubexp() {
			panic("secret_patterns.json: pattern " + p.Kind + " needs a kind, title, https source and a group " +
				"its pattern captures")
		}
	}
	return c
})

// Scan returns the credentials and identifiers in text, in order, each value
// once.
func Scan(text string) []Find {
	c := loadCatalog()
	var out []Find
	seen := map[string]bool{}
	for _, p := range c.Patterns {
		for _, m := range p.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := m[2*p.Group], m[2*p.Group+1]
			if start < 0 {
				continue
			}
			v := text[start:end]
			if seen[p.Kind+"\x00"+v] || c.ignored(v) || (p.IDType == "" && entropy(v) < p.MinEntropy) {
				continue
			}
			seen[p.Kind+"\x00"+v] = true
			sum := sha256.Sum256([]byte(v))
			out = append(out, Find{Kind: p.Kind, Title: p.Title, IDType: p.IDType, Value: v,
				Hash: hex.EncodeToString(sum[:]), Preview: preview(p, v), Start: start, End: end})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

// Mask returns text with every secret Scan finds replaced by its masked
// preview. Identifiers are left as they are.
func Mask(text string) string {
	finds := Scan(text)
	if len(finds) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, f := range finds {
		if !f.Secret() || f.Start < last {
			continue
		}
		b.WriteString(text[last:f.Start])
		b.WriteString("[" + f.Kind + " " + f.Preview + "]")
		last = f.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// ignored reports whether a value is a documentation example.
func (c catalog) ignored(v string) bool {
	for _, x := range c.IgnoreValues {
		if v == x {
			return true
		}
	}
	for _, s := range c.IgnoreSubstrings {
		if strings.Contains(v, s) {
			return true
		}
	}
	return false
}

// preview masks a value: an identifier is shown in full; a secret keeps its
// first and last four characters, a private key only its armor.
func preview(p pattern, v string) string {
	if p.IDType != "" {
		return v
	}
	if strings.HasPrefix(v, "-----BEGIN ") {
		if i := strings.Index(v, "-----\n"); i > 0 {
			return v[:i+5] + "…"
		}
		return "-----BEGIN …PRIVATE KEY-----"
	}
	if len(v) < 12 {
		return strings.Repeat("*", len(v))
	}
	return v[:4] + "…" + v[len(v)-4:]
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

// AWSAccountFromKeyID decodes the AWS account ID an access key ID (AKIA… or
// ASIA…) carries: its characters after the prefix are base32, and bits
// 1-40 of the first six bytes are the account number (the technique Aidan
// Steele published). It returns "" when the key ID is not one.
func AWSAccountFromKeyID(keyID string) string {
	if len(keyID) != 20 || (!strings.HasPrefix(keyID, "AKIA") && !strings.HasPrefix(keyID, "ASIA")) {
		return ""
	}
	raw, err := base32.StdEncoding.DecodeString(keyID[4:])
	if err != nil || len(raw) < 6 {
		return ""
	}
	var b [8]byte
	copy(b[2:], raw[:6])
	n := (binary.BigEndian.Uint64(b[:]) & 0x7fffffffff80) >> 7
	s := strconv.FormatUint(n, 10)
	return strings.Repeat("0", max(0, 12-len(s))) + s
}
