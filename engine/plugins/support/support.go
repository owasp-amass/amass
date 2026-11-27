// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/sessions"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdb "github.com/owasp-amass/amass/v5/internal/db"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	"github.com/owasp-amass/amass/v5/internal/net/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/url"
	xurls "mvdan.cc/xurls/v2"
)

const (
	MinHandlerInstances  int = 4
	MidHandlerInstances  int = 16
	HighHandlerInstances int = 32
	MaxHandlerInstances  int = 64
)

type SweepCallback func(d *et.Event, addr *oamnet.IPAddress, src *et.Source)

var done chan struct{}
var subre, urlre *regexp.Regexp

func init() {
	done = make(chan struct{})

	urlre = xurls.Relaxed()
	subre = regexp.MustCompile(dns.AnySubdomainRegexString())
}

func ScrapeSubdomainNames(s string) []string {
	set := stringset.New()
	defer set.Close()

	for _, sub := range subre.FindAllString(s, -1) {
		if sub != "" {
			set.Insert(sub)
		}
	}

	return set.Slice()
}

func ExtractURLFromString(s string) *url.URL {
	for _, match := range urlre.FindAllString(s, -1) {
		if u := webURL(match); u != nil {
			return u
		}
	}
	return nil
}

func ExtractURLsFromString(s string) []*url.URL {
	var results []*url.URL

	for _, match := range urlre.FindAllString(s, -1) {
		if u := webURL(match); u != nil {
			results = append(results, u)
		}
	}
	return results
}

// webURL turns a match of the relaxed URL pattern into a web URL, or nil when
// it is not one. The pattern also matches email addresses and other schemes
// ("mailto:helpdesk@example.edu", "tel:+1…"); prefixing those with http://
// made fake URLs whose "username" was the mailbox, so a match with a scheme
// other than http(s), or without a scheme but with an "@", is not a web URL.
// Email addresses are extracted separately (ExtractEmailsFromString).
func webURL(match string) *url.URL {
	if match == "" {
		return nil
	}
	// a link read from HTML carries its character references ("&amp;"
	// between query parameters); the URL is the unescaped text
	match = html.UnescapeString(match)
	// a URL ends where an unescaped bracket or quote starts: the relaxed
	// pattern also takes the "&gt;" closing an HTTP Link header
	// ("<https://example.edu/?p=1>; rel=shortlink"), which unescapes to ">"
	if i := strings.IndexAny(match, "<>\"'`"); i >= 0 {
		match = match[:i]
	}
	match = strings.TrimRight(match, ".,;:!?")
	if match == "" {
		return nil
	}

	lower := strings.ToLower(match)
	switch {
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
	case schemere.MatchString(lower):
		// mailto:, tel:, ftp:, data:, javascript: and other non-web schemes
		return nil
	case strings.Contains(strings.SplitN(match, "/", 2)[0], "@"):
		// a bare email address (an "@" before any path), not a host
		return nil
	default:
		match = "http://" + match
	}

	return RawURLToOAM(match)
}

// WebURL turns a link read from a document, page or record into a web URL,
// or nil when it is not one (webURL): a mailto: or tel: link, or a bare email
// address, is none, and the URL ends where an unescaped bracket or quote
// starts.
func WebURL(raw string) *url.URL { return webURL(strings.TrimSpace(raw)) }

// MalformedURL reports whether a URL holds characters a well-formed URL
// escapes: whitespace, brackets, quotes or a backtick. Archives and crawlers
// record links cut out of broken markup ("…/?subject='To" from a mailto: link
// read as a relative one); such a capture names no real page.
func MalformedURL(raw string) bool {
	return strings.ContainsAny(raw, "<>\"'`{}| \t\r\n")
}

// schemere matches a leading URI scheme ("mailto:", "tel:"), but not a host
// with a port ("example.com:8080").
var schemere = regexp.MustCompile(`^[a-z][a-z0-9+.-]*:[^0-9]`)

// emailre matches email addresses in free text.
var emailre = regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b`)

// ExtractEmailsFromString returns the distinct email addresses in s, in
// lowercase and in the order first seen.
func ExtractEmailsFromString(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range emailre.FindAllString(s, -1) {
		m = strings.ToLower(strings.TrimRight(m, "."))
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

func Shutdown() {
	close(done)
}

func TTLStartTime(c *config.Config, from, to, plugin string) (time.Time, error) {
	now := time.Now()

	if matches, err := c.CheckTransformations(from, to, plugin); err == nil && matches != nil {
		if ttl := matches.TTL(plugin); ttl >= 0 {
			return now.Add(time.Duration(-ttl) * time.Minute), nil
		}
		if ttl := matches.TTL(to); ttl >= 0 {
			return now.Add(time.Duration(-ttl) * time.Minute), nil
		}
	}

	return time.Time{}, fmt.Errorf("failed to obtain the TTL for transformation %s->%s", from, to)
}

func GetAPI(name string, e *et.Event) (string, error) {
	// TODO: Add support for multiple API keys
	dsc := e.Session.Config().GetDataSourceConfig(name)
	if dsc == nil || len(dsc.Creds) == 0 {
		return "", errors.New("no API key found")
	}

	for _, cred := range dsc.Creds {
		if cred != nil && cred.Apikey != "" {
			return cred.Apikey, nil
		}
	}

	return "", errors.New("no API key found")
}

func IPNetblock(session et.Session, addrstr string) *sessions.CIDRangerEntry {
	ip := net.ParseIP(addrstr)
	if ip == nil {
		return nil
	}

	entries, err := session.CIDRanger().ContainingNetworks(ip)
	if err != nil || len(entries) == 0 {
		return nil
	}

	var bits int
	var arentry *sessions.CIDRangerEntry
	for _, entry := range entries {
		e, ok := entry.(*sessions.CIDRangerEntry)
		if !ok {
			continue
		}

		n := e.Net
		if ones, _ := n.Mask.Size(); ones > bits {
			bits = ones
			arentry = e
		}
	}

	return arentry
}

func AddNetblock(session et.Session, cidr string, asn int, src *et.Source) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	return session.CIDRanger().Insert(&sessions.CIDRangerEntry{
		Net: ipnet,
		ASN: asn,
		Src: src,
	})
}

func IPAddressSweep(e *et.Event, addr *oamnet.IPAddress, src *et.Source, size int, callback SweepCallback) {
	var mask net.IPMask
	addrstr := addr.Address.String()
	ip := net.ParseIP(addrstr)

	if amassnet.IsIPv4(ip) {
		mask = net.CIDRMask(18, 32)
	} else if amassnet.IsIPv6(ip) {
		mask = net.CIDRMask(64, 128)
	}

	cidr := &net.IPNet{
		IP:   ip.Mask(mask),
		Mask: mask,
	}

	for _, ip := range amassnet.CIDRSubset(cidr, addrstr, size) {
		a := oamnet.IPAddress{
			Type:    "IPv4",
			Address: netip.MustParseAddr(ip.String()),
		}
		if a.Address.Is6() {
			a.Type = "IPv6"
		}
		callback(e, &a, src)
	}
}

func IsRegisteredDomain(session et.Session, fqdn *dbt.Entity) bool {
	if _, valid := fqdn.Asset.(*oamdns.FQDN); !valid {
		return false
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 10*time.Second)
	defer cancel()

	matches, err := session.Config().CheckTransformations(string(oam.FQDN), string(oam.FQDN))
	if err != nil || matches == nil {
		return false
	}

	var since time.Time
	if ttl := matches.TTL(string(oam.FQDN)); ttl >= 0 {
		since = time.Now().Add(time.Duration(-ttl) * time.Minute)
	}
	if since.IsZero() {
		return false
	}

	if edges, err := session.DB().IncomingEdges(ctx, fqdn, since, "node"); err == nil && len(edges) > 0 {
		return false
	}
	return true
}

func IsCNAME(session et.Session, name *oamdns.FQDN) (*oamdns.FQDN, bool) {
	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	ents, err := session.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{
		"name": name.Name,
	})
	if err != nil {
		return nil, false
	}

	if edges, err := session.DB().OutgoingEdges(ctx, ents[0], time.Time{}, "dns_record"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if rec, ok := edge.Relation.(*oamdns.BasicDNSRelation); ok && rec.Header.RRType == 5 {
				if to, err := session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
					if cname, ok := to.Asset.(*oamdns.FQDN); ok {
						return cname, true
					}
				}
			}
		}
	}
	return nil, false
}

func NameIPAddresses(session et.Session, name *oamdns.FQDN) []*oamnet.IPAddress {
	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	ents, err := session.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{
		"name": name.Name,
	})
	if err != nil {
		return nil
	}
	fqdn := ents[0]

	since, err := TTLStartTime(session.Config(), string(oam.FQDN), string(oam.IPAddress), "")
	if err != nil {
		return nil
	}

	var results []*oamnet.IPAddress
	if edges, err := session.DB().OutgoingEdges(ctx, fqdn, since, "dns_record"); err == nil && len(edges) > 0 {
		var addrs []*dbt.Edge
		for _, edge := range edges {
			if rec, ok := edge.Relation.(*oamdns.BasicDNSRelation); ok && (rec.Header.RRType == 1 || rec.Header.RRType == 28) {
				addrs = append(addrs, edge)
			}
		}
		ends := amassdb.EdgeEnds(ctx, session.DB(), addrs, false)
		for _, edge := range addrs {
			if to, ok := ends[edge.ToEntity.ID]; ok {
				if ip, ok := to.Asset.(*oamnet.IPAddress); ok {
					results = append(results, ip)
				}
			}
		}
	}

	if len(results) > 0 {
		return results
	}
	return nil
}

func NameResolved(session et.Session, name *oamdns.FQDN) bool {
	if _, found := IsCNAME(session, name); found {
		return true
	}
	if ips := NameIPAddresses(session, name); len(ips) > 0 {
		return true
	}
	return false
}

type FQDNMeta struct {
	SLDInScope  bool
	RecordTypes map[int]bool
	// FromRecord marks an FQDN obtained from an authoritative DNS record (a
	// CNAME target), rather than generated by brute force or name alteration.
	// Its resolution skips wildcard suppression: DNS already proved the name
	// exists, so its address is recorded even when the name's zone serves a
	// wildcard (see PerformQueryNoWildcard).
	FromRecord bool
}

func AddSLDInScope(e *et.Event) {
	if e == nil {
		return
	} else if _, ok := e.Entity.Asset.(*oamdns.FQDN); !ok {
		return
	}

	if e.Meta == nil {
		e.Meta = &FQDNMeta{
			SLDInScope: true,
		}
		return
	}

	if fm, ok := e.Meta.(*FQDNMeta); ok {
		fm.SLDInScope = true
	}
}

func HasSLDInScope(e *et.Event) bool {
	if e == nil {
		return false
	} else if _, ok := e.Entity.Asset.(*oamdns.FQDN); !ok {
		return false
	}

	if e.Meta == nil {
		return false
	}

	if fm, ok := e.Meta.(*FQDNMeta); ok {
		return fm.SLDInScope
	}
	return false
}

func AddDNSRecordType(e *et.Event, rrtype int) {
	if e == nil {
		return
	} else if _, ok := e.Entity.Asset.(*oamdns.FQDN); !ok {
		return
	}

	if e.Meta == nil {
		e.Meta = &FQDNMeta{
			RecordTypes: make(map[int]bool),
		}
	}

	if fm, ok := e.Meta.(*FQDNMeta); ok {
		if fm.RecordTypes == nil {
			fm.RecordTypes = make(map[int]bool)
		}
		fm.RecordTypes[rrtype] = true
	}
}

func HasDNSRecordType(e *et.Event, rrtype int) bool {
	if e == nil {
		return false
	} else if _, ok := e.Entity.Asset.(*oamdns.FQDN); !ok {
		return false
	}

	if e.Meta == nil {
		return false
	}

	if fm, ok := e.Meta.(*FQDNMeta); ok && fm.RecordTypes != nil {
		if _, found := fm.RecordTypes[rrtype]; found {
			return true
		}
	}
	return false
}
