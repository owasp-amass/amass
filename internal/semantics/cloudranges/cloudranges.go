// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package cloudranges attributes an IP address to the public cloud or CDN
// provider that operates it, and often the provider's region and service,
// from the ranges the provider itself publishes. The catalog of providers
// and their feeds is data (internal/semantics/cloud_providers.json); this
// package reads a feed's already-fetched bytes into attributed prefixes and
// matches an address against them by longest prefix. It does no network I/O
// and writes nothing: fetching feeds and recording observations are the
// engine's job.
//
// Attribution here is a hosting fact, never ownership: an address falling in
// a provider's published range means the provider operates that network, not
// that the provider owns the customer's assets, and two parties on the same
// provider are not related (ai-design-principles.md, principle 8).
package cloudranges

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Provider is one cloud or CDN provider from the catalog.
type Provider struct {
	Key          string   `json:"key"`
	Organization string   `json:"organization"`
	RegionLabel  string   `json:"region_label"`
	ServiceLabel string   `json:"service_label"`
	ASNHints     []string `json:"asn_hints"`
	// Names are alias spellings of the provider's stored hosting-organization
	// label (for example "amazon" or "amazon data services" for AWS), used to
	// recognize a host already attributed by registration as this provider.
	Names []string `json:"names"`
	// Domains are the provider-operated CNAME/alias domains a customer name
	// points at when the provider fronts it (for example azurefd.net,
	// cloudfront.net), used to recognize edge/CDN hosting from an alias alone.
	Domains []string `json:"domains"`
	Feeds   []Feed   `json:"feeds"`
	Source  string   `json:"source"`
}

// Feed is one published range list of a provider.
type Feed struct {
	URL        string `json:"url"`
	Format     string `json:"format"`
	HasRegion  bool   `json:"has_region"`
	HasService bool   `json:"has_service"`
	// LinkPattern, when set, means URL is a page that links to the feed
	// file, whose name changes with each release (Microsoft's weekly
	// service tags file): the first link on the page matching the pattern
	// is the file to fetch (FeedLink).
	LinkPattern string `json:"link_pattern,omitempty"`
	// ExcludeServices are services the feed lists that run on another
	// provider's network, so their ranges are that provider's, not this
	// one's (GitHub's hosted Actions runners and Codespaces run in Azure).
	ExcludeServices []string `json:"exclude_services,omitempty"`
}

// FeedLink returns the feed file a page links to: the first URL on the page
// that matches the feed's LinkPattern.
func FeedLink(f Feed, page []byte) (string, error) {
	if f.LinkPattern == "" {
		return f.URL, nil
	}
	re, err := regexp.Compile(f.LinkPattern)
	if err != nil {
		return "", fmt.Errorf("cloudranges: the link pattern of %s: %w", f.URL, err)
	}
	link := re.Find(page)
	if link == nil {
		return "", fmt.Errorf("cloudranges: %s links to no feed file", f.URL)
	}
	return string(link), nil
}

// Prefix is one attributed CIDR read from a feed.
type Prefix struct {
	Prefix  netip.Prefix
	Region  string
	Service string
}

type catalog struct {
	License   string     `json:"_license"`
	About     string     `json:"_about"`
	Providers []Provider `json:"providers"`
}

var loadCatalog = sync.OnceValue(func() []Provider {
	var c catalog
	if err := strictDecode(semantics.File("cloud_providers.json"), &c); err != nil {
		panic("cloud_providers.json: " + err.Error())
	}
	seen := map[string]bool{}
	for _, p := range c.Providers {
		if p.Key == "" || p.Organization == "" || len(p.Feeds) == 0 {
			panic("cloud_providers.json: each provider needs a key, organization and at least one feed")
		}
		if seen[p.Key] {
			panic("cloud_providers.json: duplicate provider key " + p.Key)
		}
		seen[p.Key] = true
		for _, f := range p.Feeds {
			if f.URL == "" || parsers[f.Format] == nil {
				panic("cloud_providers.json: provider " + p.Key + " has a feed with no url or an unknown format " + f.Format)
			}
		}
	}
	return c.Providers
})

// Providers returns the catalog of cloud and CDN providers, loaded once.
func Providers() []Provider { return loadCatalog() }

// ProviderByKey returns the catalog provider with the given key, or false.
func ProviderByKey(key string) (Provider, bool) {
	for _, p := range Providers() {
		if p.Key == key {
			return p, true
		}
	}
	return Provider{}, false
}

// ProviderByName returns the catalog provider whose name aliases match a
// stored hosting-organization label, and false when none do. Matching is
// case-insensitive and token-based: an alias matches when its words appear, in
// order and adjacent, among the label's words, so "amazon" matches
// "amazon.com" and "amazon data services" matches "amazon data services
// northern virginia", while a short alias such as "aws" matches only a whole
// "aws" word, never a fragment of a longer one.
func ProviderByName(label string) (Provider, bool) {
	have := tokens(label)
	if len(have) == 0 {
		return Provider{}, false
	}
	for _, p := range Providers() {
		for _, alias := range p.Names {
			if containsTokens(have, tokens(alias)) {
				return p, true
			}
		}
	}
	return Provider{}, false
}

// ProviderByDomain returns the catalog provider that operates a CNAME/alias
// domain (a provider-run hosting domain such as azurefd.net or cloudfront.net),
// and false when none do. The domain matches a catalog domain exactly or as a
// subdomain of it.
func ProviderByDomain(domain string) (Provider, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return Provider{}, false
	}
	for _, p := range Providers() {
		for _, d := range p.Domains {
			d = strings.ToLower(d)
			if domain == d || strings.HasSuffix(domain, "."+d) {
				return p, true
			}
		}
	}
	return Provider{}, false
}

// tokens splits a label into lowercase alphanumeric words.
func tokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// containsTokens reports whether want appears, in order and adjacent, in have.
func containsTokens(have, want []string) bool {
	if len(want) == 0 || len(want) > len(have) {
		return false
	}
	for i := 0; i+len(want) <= len(have); i++ {
		ok := true
		for j := range want {
			if have[i+j] != want[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// ParseFeed reads a feed's already-fetched bytes into attributed prefixes,
// using the parser named by the feed's Format. Region and service are kept
// only when the feed declares that it carries them.
func ParseFeed(f Feed, data []byte) ([]Prefix, error) {
	parse := parsers[f.Format]
	if parse == nil {
		return nil, fmt.Errorf("cloudranges: unknown feed format %q", f.Format)
	}
	out, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("cloudranges: %s feed: %w", f.Format, err)
	}
	kept := out[:0]
	for _, p := range out {
		if slices.ContainsFunc(f.ExcludeServices, func(s string) bool { return strings.EqualFold(s, p.Service) }) {
			continue
		}
		if !f.HasRegion {
			p.Region = ""
		}
		if !f.HasService {
			p.Service = ""
		}
		kept = append(kept, p)
	}
	return kept, nil
}

// Match is the attribution of an address to a provider.
type Match struct {
	ProviderKey  string
	Organization string
	Region       string
	Service      string
	Prefix       netip.Prefix
}

// Matcher attributes an address to a provider by the longest published
// prefix that contains it. It is safe for concurrent Match calls once built;
// Add is not concurrent with Match.
type Matcher struct {
	meta map[string]Provider
	v4   lpm
	v6   lpm
}

// NewMatcher returns an empty matcher.
func NewMatcher() *Matcher {
	return &Matcher{meta: map[string]Provider{}, v4: newLPM(), v6: newLPM()}
}

// Add records a provider's prefixes. A later Add for the same address and
// prefix length replaces the earlier entry, so a more specific feed wins by
// length and the last writer wins on an exact tie.
func (m *Matcher) Add(p Provider, prefixes []Prefix) {
	m.meta[p.Key] = p
	for _, pre := range prefixes {
		canon := pre.Prefix.Masked()
		e := entry{provider: p.Key, region: pre.Region, service: pre.Service, prefix: canon}
		if canon.Addr().Is6() {
			m.v6.add(canon, e)
		} else {
			m.v4.add(canon, e)
		}
	}
}

// Match returns the provider operating an address, by the longest published
// prefix that contains it, and false when none does.
func (m *Matcher) Match(addr netip.Addr) (Match, bool) {
	addr = addr.Unmap()
	table := &m.v4
	if addr.Is6() {
		table = &m.v6
	}

	e, ok := table.lookup(addr)
	if !ok {
		return Match{}, false
	}
	p := m.meta[e.provider]
	return Match{ProviderKey: e.provider, Organization: p.Organization, Region: e.region,
		Service: e.service, Prefix: e.prefix}, true
}

type entry struct {
	provider string
	region   string
	service  string
	prefix   netip.Prefix
}

// lpm is a longest-prefix-match table: prefixes grouped by length, so a
// lookup probes each present length from the most specific down.
type lpm struct {
	byLen   map[int]map[netip.Prefix]entry
	lengths []int // present prefix lengths, descending
}

func newLPM() lpm { return lpm{byLen: map[int]map[netip.Prefix]entry{}} }

func (t *lpm) add(canon netip.Prefix, e entry) {
	bits := canon.Bits()
	m, ok := t.byLen[bits]
	if !ok {
		m = map[netip.Prefix]entry{}
		t.byLen[bits] = m
		t.lengths = append(t.lengths, bits)
		sort.Sort(sort.Reverse(sort.IntSlice(t.lengths)))
	}
	m[canon] = e
}

func (t *lpm) lookup(addr netip.Addr) (entry, bool) {
	for _, bits := range t.lengths {
		p, err := addr.Prefix(bits)
		if err != nil {
			continue
		}
		if e, ok := t.byLen[bits][p]; ok {
			return e, true
		}
	}
	return entry{}, false
}

// parsers reads each provider feed format into attributed prefixes. A format
// named in the catalog must have a parser here; the field names each parser
// reads are the provider's own published schema, cited in the catalog.
var parsers = map[string]func([]byte) ([]Prefix, error){
	"aws":              parseAWS,
	"gcp":              parseGCP,
	"azure":            parseAzure,
	"oracle":           parseOracle,
	"fastly":           parseFastly,
	"github":           parseGitHub,
	"digitalocean_csv": parseDigitalOceanCSV,
	"text":             parseText,
}

func parseAWS(data []byte) ([]Prefix, error) {
	var f struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Region     string `json:"region"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	var out []Prefix
	for _, p := range f.Prefixes {
		add(&out, p.IPPrefix, p.Region, p.Service)
	}
	for _, p := range f.IPv6Prefixes {
		add(&out, p.IPv6Prefix, p.Region, p.Service)
	}
	return out, nil
}

func parseGCP(data []byte) ([]Prefix, error) {
	var f struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
			Scope      string `json:"scope"`
			Service    string `json:"service"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	var out []Prefix
	for _, p := range f.Prefixes {
		cidr := p.IPv4Prefix
		if cidr == "" {
			cidr = p.IPv6Prefix
		}
		add(&out, cidr, p.Scope, p.Service)
	}
	return out, nil
}

func parseAzure(data []byte) ([]Prefix, error) {
	var f struct {
		Values []struct {
			Properties struct {
				Region          string   `json:"region"`
				SystemService   string   `json:"systemService"`
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	var out []Prefix
	for _, v := range f.Values {
		for _, cidr := range v.Properties.AddressPrefixes {
			add(&out, cidr, v.Properties.Region, v.Properties.SystemService)
		}
	}
	return out, nil
}

func parseOracle(data []byte) ([]Prefix, error) {
	var f struct {
		Regions []struct {
			Region string `json:"region"`
			CIDRs  []struct {
				CIDR string   `json:"cidr"`
				Tags []string `json:"tags"`
			} `json:"cidrs"`
		} `json:"regions"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	var out []Prefix
	for _, r := range f.Regions {
		for _, c := range r.CIDRs {
			add(&out, c.CIDR, r.Region, strings.Join(c.Tags, ","))
		}
	}
	return out, nil
}

func parseFastly(data []byte) ([]Prefix, error) {
	var f struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	var out []Prefix
	for _, cidr := range f.Addresses {
		add(&out, cidr, "", "")
	}
	for _, cidr := range f.IPv6Addresses {
		add(&out, cidr, "", "")
	}
	return out, nil
}

// parseGitHub reads GitHub's /meta document, whose service keys (hooks, web,
// api, git, pages, actions and the like) each hold a list of CIDRs. Keys
// that are not a list of CIDRs (booleans, fingerprints, domains) are skipped.
func parseGitHub(data []byte) ([]Prefix, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	var out []Prefix
	for service, msg := range raw {
		var cidrs []string
		if json.Unmarshal(msg, &cidrs) != nil {
			continue
		}
		for _, cidr := range cidrs {
			add(&out, cidr, "", service)
		}
	}
	return out, nil
}

// parseDigitalOceanCSV reads DigitalOcean's geofeed CSV: prefix, country,
// region (ISO subdivision), city, postal code. Only the prefix and region
// are kept.
func parseDigitalOceanCSV(data []byte) ([]Prefix, error) {
	var out []Prefix
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		region := ""
		if len(fields) >= 3 {
			region = strings.TrimSpace(fields[2])
		}
		add(&out, strings.TrimSpace(fields[0]), region, "")
	}
	return out, sc.Err()
}

// parseText reads a plain list of one CIDR per line, skipping blanks and
// comments.
func parseText(data []byte) ([]Prefix, error) {
	var out []Prefix
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		add(&out, line, "", "")
	}
	return out, sc.Err()
}

// add appends an attributed prefix, accepting either a CIDR or a bare address
// (taken as a host route). An unparseable entry is skipped: a provider feed
// carries far more than Amass needs, and one malformed line should not fail
// the whole feed.
func add(out *[]Prefix, cidr, region, service string) {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return
	}
	if p, err := netip.ParsePrefix(cidr); err == nil {
		*out = append(*out, Prefix{Prefix: p, Region: region, Service: service})
		return
	}
	if a, err := netip.ParseAddr(cidr); err == nil {
		*out = append(*out, Prefix{Prefix: netip.PrefixFrom(a, a.BitLen()), Region: region, Service: service})
	}
}

// strictDecode decodes JSON rejecting unknown fields and trailing content, so
// a typo in the catalog is a build-time panic rather than a silent default.
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
