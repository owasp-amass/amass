// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package breachsources reads the defensive breach-exposure sources' responses
// into breach-exposure metadata: which known breaches an email or domain
// appears in, when, and the categories of data exposed. The catalog of sources
// and their endpoints is data (internal/semantics/breach_sources.json); this
// package parses an already-fetched response and does no network I/O and
// writes nothing — fetching and recording are the engine's job.
//
// It handles metadata only. A breach record names the breach, its date and the
// exposed data classes (categories such as "Passwords"), never a leaked secret
// (ai-design-principles.md): no password, hash, token or dumped record is read
// or produced.
package breachsources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Source is one breach-exposure source from the catalog.
type Source struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	Free         bool   `json:"free"`
	RequiresKey  bool   `json:"requires_key"`
	EmailURL     string `json:"email_url"`
	EmailFormat  string `json:"email_format"`
	DomainURL    string `json:"domain_url"`
	DomainFormat string `json:"domain_format"`
	Source       string `json:"source"`
}

// Record is one breach an address or domain appears in: metadata only.
type Record struct {
	Breach      string
	Title       string
	Date        string
	DataClasses []string
	Verified    bool
}

type catalog struct {
	License string   `json:"_license"`
	About   string   `json:"_about"`
	Sources []Source `json:"sources"`
}

var loadCatalog = sync.OnceValue(func() []Source {
	var c catalog
	if err := strictDecode(semantics.File("breach_sources.json"), &c); err != nil {
		panic("breach_sources.json: " + err.Error())
	}
	seen := map[string]bool{}
	for _, s := range c.Sources {
		if s.Key == "" || s.Name == "" || s.EmailURL == "" || s.Source == "" {
			panic("breach_sources.json: each source needs a key, name, email_url and source")
		}
		if seen[s.Key] {
			panic("breach_sources.json: duplicate source key " + s.Key)
		}
		seen[s.Key] = true
		// A named format must have a parser; an empty format is a deferred
		// endpoint wired during integration.
		if s.EmailFormat != "" && parsers[s.EmailFormat] == nil {
			panic("breach_sources.json: source " + s.Key + " has an unknown email format " + s.EmailFormat)
		}
		if s.DomainFormat != "" && parsers[s.DomainFormat] == nil {
			panic("breach_sources.json: source " + s.Key + " has an unknown domain format " + s.DomainFormat)
		}
	}
	return c.Sources
})

// Sources returns the catalog of breach-exposure sources, loaded once.
func Sources() []Source { return loadCatalog() }

// SourceByKey returns the catalog source with the given key, or false.
func SourceByKey(key string) (Source, bool) {
	for _, s := range Sources() {
		if s.Key == key {
			return s, true
		}
	}
	return Source{}, false
}

// Parse reads a source response's already-fetched bytes into breach records,
// using the parser named by format.
func Parse(format string, data []byte) ([]Record, error) {
	parse := parsers[format]
	if parse == nil {
		return nil, fmt.Errorf("breachsources: unknown response format %q", format)
	}
	out, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("breachsources: %s: %w", format, err)
	}
	for i := range out {
		sort.Strings(out[i].DataClasses)
	}
	return out, nil
}

// parsers reads each source's published response into breach records. The
// field names each parser reads are the source's own documented schema, cited
// in the catalog.
var parsers = map[string]func([]byte) ([]Record, error){
	"xon_analytics": parseXONAnalytics,
	"hibp_account":  parseHIBPAccount,
}

// parseXONAnalytics reads XposedOrNot's breach-analytics response for an
// email: ExposedBreaches.breaches_details, each with the breach name, year,
// semicolon-separated data classes and a verified flag.
func parseXONAnalytics(data []byte) ([]Record, error) {
	// "Not found" responses carry an Error field and no breaches.
	var f struct {
		ExposedBreaches struct {
			BreachesDetails []struct {
				Breach     string `json:"breach"`
				XposedData string `json:"xposed_data"`
				XposedDate string `json:"xposed_date"`
				Verified   string `json:"verified"`
			} `json:"breaches_details"`
		} `json:"ExposedBreaches"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	var out []Record
	for _, b := range f.ExposedBreaches.BreachesDetails {
		if b.Breach == "" {
			continue
		}
		out = append(out, Record{
			Breach:      b.Breach,
			Title:       b.Breach,
			Date:        b.XposedDate,
			DataClasses: splitClasses(b.XposedData, ";"),
			Verified:    strings.EqualFold(strings.TrimSpace(b.Verified), "yes"),
		})
	}
	return out, nil
}

// parseHIBPAccount reads Have I Been Pwned's breachedaccount response: an
// array of breaches with a name, title, date, data classes and verified flag.
func parseHIBPAccount(data []byte) ([]Record, error) {
	var f []struct {
		Name        string   `json:"Name"`
		Title       string   `json:"Title"`
		BreachDate  string   `json:"BreachDate"`
		DataClasses []string `json:"DataClasses"`
		IsVerified  bool     `json:"IsVerified"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	var out []Record
	for _, b := range f {
		if b.Name == "" {
			continue
		}
		title := b.Title
		if title == "" {
			title = b.Name
		}
		out = append(out, Record{
			Breach:      b.Name,
			Title:       title,
			Date:        b.BreachDate,
			DataClasses: append([]string(nil), b.DataClasses...),
			Verified:    b.IsVerified,
		})
	}
	return out, nil
}

// splitClasses splits a separated data-class string into trimmed, non-empty
// categories.
func splitClasses(s, sep string) []string {
	var out []string
	for _, part := range strings.Split(s, sep) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// strictDecode decodes JSON rejecting unknown fields and trailing content.
func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON")
	}
	return nil
}
