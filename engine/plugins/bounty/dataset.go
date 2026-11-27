// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bounty

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	"golang.org/x/net/publicsuffix"
)

// program is one public bug-bounty program and the assets its scope lists.
type program struct {
	platform semantics.BountyPlatform
	handle   string
	name     string
	page     string
	website  string
	// hosts are the names the scope lists; a wildcard (*.example.com) is
	// recorded as its base name.
	hosts    []string
	prefixes []netip.Prefix
}

// id is the program Account's unique ID, <platform>:<handle>.
func (p *program) id() string { return p.platform.Key + ":" + p.handle }

// dataset is every program the platforms publish, indexed by the registered
// domains their scopes list.
type dataset struct {
	programs []*program
	byDomain map[string][]*program
}

func newDataset() *dataset { return &dataset{byDomain: map[string][]*program{}} }

// add indexes a program under each registered domain its scope lists.
func (d *dataset) add(p *program) {
	d.programs = append(d.programs, p)
	seen := map[string]bool{}
	for _, h := range p.hosts {
		dom, err := publicsuffix.EffectiveTLDPlusOne(h)
		if err != nil || seen[dom] {
			continue
		}
		seen[dom] = true
		d.byDomain[dom] = append(d.byDomain[dom], p)
	}
}

// lookup returns the programs whose scope lists a name under the registered
// domain.
func (d *dataset) lookup(domain string) []*program {
	return d.byDomain[strings.ToLower(domain)]
}

// rawRecord is one program record of a platform feed. The four platforms name
// their fields differently, so fields are read by name, tolerating strings
// and numbers.
type rawRecord map[string]json.RawMessage

func (r rawRecord) str(key string) string {
	raw, ok := r[key]
	if !ok {
		return ""
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

func (r rawRecord) truth(key string) bool {
	var b bool
	return json.Unmarshal(r[key], &b) == nil && b
}

// targetFields are the fields of a scope entry that can hold the asset, in
// the order tried: HackerOne's asset_identifier, Bugcrowd's target and uri,
// Intigriti's endpoint, YesWeHack's target.
var targetFields = []string{"asset_identifier", "target", "endpoint", "uri"}

// parseFeed reads a platform's feed: a JSON array of program records, each
// with targets.in_scope entries. Out-of-scope entries are ignored: they are
// mostly vendors' services the program excludes.
func parseFeed(plat semantics.BountyPlatform, r io.Reader, d *dataset) error {
	var records []rawRecord
	if err := json.NewDecoder(r).Decode(&records); err != nil {
		return fmt.Errorf("%s feed: %w", plat.Key, err)
	}

	for _, rec := range records {
		if rec.truth("disabled") {
			continue
		}
		p := &program{platform: plat, name: rec.str("name"), website: rec.str("website")}
		p.handle = recordHandle(plat, rec)
		if p.handle == "" {
			continue
		}
		p.page = rec.str("url")
		if !strings.HasPrefix(p.page, "https://") {
			p.page = plat.ProgramPage(p.handle)
		}

		var targets struct {
			InScope []rawRecord `json:"in_scope"`
		}
		if raw, ok := rec["targets"]; !ok || json.Unmarshal(raw, &targets) != nil {
			continue
		}
		hosts, prefixes := map[string]bool{}, map[netip.Prefix]bool{}
		for _, t := range targets.InScope {
			if appTarget(t.str("asset_type") + " " + t.str("type")) {
				continue
			}
			for _, f := range targetFields {
				host, prefix, ok := parseTarget(t.str(f))
				switch {
				case !ok:
				case prefix.IsValid():
					prefixes[prefix] = true
				case host != "" && !plat.OwnsHost(host):
					hosts[host] = true
				}
			}
		}
		if len(hosts)+len(prefixes) == 0 {
			continue
		}
		for h := range hosts {
			p.hosts = append(p.hosts, h)
		}
		for pf := range prefixes {
			p.prefixes = append(p.prefixes, pf)
		}
		d.add(p)
	}
	return nil
}

// recordHandle returns a program's handle on its platform: the first of the
// platform's handle fields that is set (with the company handle in front
// when the platform scopes handles by company), else the last segment of the
// program's page.
func recordHandle(plat semantics.BountyPlatform, rec rawRecord) string {
	var handle string
	for _, f := range plat.HandleFields {
		if handle = rec.str(f); handle != "" {
			break
		}
	}
	if handle == "" {
		if u, err := url.Parse(rec.str("url")); err == nil {
			segs := strings.FieldsFunc(u.Path, func(r rune) bool { return r == '/' })
			if len(segs) > 0 {
				handle = segs[len(segs)-1]
			}
		}
	}
	if handle == "" {
		return ""
	}
	if plat.CompanyField != "" {
		if company := rec.str(plat.CompanyField); company != "" && !strings.Contains(handle, "/") {
			handle = company + "/" + handle
		}
	}
	return strings.ToLower(handle)
}

// appTypes are words in a scope entry's type that mark an app, a repository,
// a binary or a device rather than a host: HackerOne's GOOGLE_PLAY_APP_ID,
// Bugcrowd's android, YesWeHack's mobile-application-ios and so on.
var appTypes = []string{"app_id", "android", "ios", "mobile", "source_code", "executable", "hardware",
	"smart_contract", "device", "apple_store", "play_store", "windows_app"}

// appTarget reports whether a scope entry's type marks it as no host.
func appTarget(kind string) bool {
	kind = strings.ToLower(kind)
	for _, w := range appTypes {
		if strings.Contains(kind, w) {
			return true
		}
	}
	return false
}

// reverseRoots are the top-level domains that start an app or package ID
// written in reverse-domain order (com.example.android), which can read as a
// valid host name under a newer TLD (.android, .app).
var reverseRoots = map[string]bool{"com": true, "org": true, "net": true, "edu": true, "gov": true, "io": true,
	"co": true, "de": true, "fr": true, "nl": true, "uk": true, "ch": true, "se": true, "jp": true}

// reverseDomainID reports whether a name is a reverse-domain ID: it starts
// with a common TLD and does not end with one.
func reverseDomainID(s string) bool {
	labels := strings.Split(s, ".")
	return len(labels) >= 3 && reverseRoots[labels[0]] && !reverseRoots[labels[len(labels)-1]]
}

// Address ranges broader than these say nothing about one organization.
const (
	minIPv4Bits = 16
	minIPv6Bits = 32
)

// parseTarget reads one scope entry: a CIDR or address as a prefix, or a URL,
// host or wildcard as a host name (a wildcard as its base name). Entries
// that are neither, such as an app ID, a repository or prose, are skipped,
// as are names without an ICANN public suffix and wildcards anywhere but in
// front.
func parseTarget(raw string) (host string, prefix netip.Prefix, ok bool) {
	fields := strings.Fields(strings.ToLower(raw))
	if len(fields) == 0 {
		return "", netip.Prefix{}, false
	}
	s := strings.Trim(fields[0], ",;\"'()<>")

	if pf, err := netip.ParsePrefix(s); err == nil {
		pf = pf.Masked()
		if (pf.Addr().Is4() && pf.Bits() < minIPv4Bits) || (pf.Addr().Is6() && pf.Bits() < minIPv6Bits) {
			return "", netip.Prefix{}, false
		}
		return "", pf, true
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return "", netip.PrefixFrom(addr, addr.BitLen()), true
	}

	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if h, _, found := strings.Cut(s, ":"); found {
		s = h
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "*"), ".")
	s = strings.TrimSuffix(s, ".")
	if amassdns.HostName(s) != s || reverseDomainID(s) {
		return "", netip.Prefix{}, false
	}
	return s, netip.Prefix{}, true
}
