// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// A domain's published mail policy names other domains: its SPF record
// authorizes a domain's senders (include:/redirect=, RFC 7208) and its DMARC
// record sends reports to a domain (rua/ruf mailto URIs, RFC 7489). These
// functions record those references as pivotable FQDN->FQDN edges so horizontal
// correlation can find a domain that points its mail policy at one of an
// organization's own domains. The raw TXT records are left untouched; the edges
// are derived from them.
const (
	relSPFAuthorizes  = "spf_authorizes"
	relDMARCReportsTo = "dmarc_reports_to"
)

// storeSPFEdges queries the apex's own TXT records, and for an SPF record
// records a spf_authorizes edge from the apex to each domain its include: or
// redirect= mechanisms name.
func (d *dnsSubs) storeSPFEdges(e *et.Event, apex *dbt.Entity, subdomain string) {
	rr, err := support.PerformQuery(e.Session.Ctx(), subdomain, dns.TypeTXT)
	if err != nil {
		return
	}
	for _, r := range rr {
		t, ok := r.(*dns.TXT)
		if !ok {
			continue
		}
		for _, domain := range spfAuthorizedDomains(txtData(t)) {
			d.storeMailPolicyEdge(e, apex, domain, relSPFAuthorizes)
		}
		for _, p := range spfAuthorizedRanges(txtData(t)) {
			d.storeSPFRange(e, apex, p)
		}
	}
}

// Ranges broader than these, in an SPF record, say nothing about one
// organization's mail servers.
const (
	spfMinIPv4Bits = 16
	spfMinIPv6Bits = 32
)

// spfAuthorizedRanges returns the address ranges an SPF record authorizes
// to send its mail, from its ip4: and ip6: mechanisms (RFC 7208 section
// 5.6): a single address is a full-length prefix. Private, reserved and
// overly broad ranges are dropped.
func spfAuthorizedRanges(txt string) []netip.Prefix {
	t := strings.TrimSpace(txt)
	if !strings.HasPrefix(strings.ToLower(t), "v=spf1") {
		return nil
	}

	var out []netip.Prefix
	for _, f := range strings.Fields(t) {
		term := strings.ToLower(strings.TrimLeft(f, "+-~?"))
		var v string
		switch {
		case strings.HasPrefix(term, "ip4:"):
			v = term[len("ip4:"):]
		case strings.HasPrefix(term, "ip6:"):
			v = term[len("ip6:"):]
		default:
			continue
		}
		// a minus qualifier excludes the range; it authorizes nothing
		if strings.HasPrefix(f, "-") {
			continue
		}
		p, err := netip.ParsePrefix(v)
		if err != nil {
			addr, aerr := netip.ParseAddr(v)
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		p = p.Masked()
		if (p.Addr().Is4() && p.Bits() < spfMinIPv4Bits) || (p.Addr().Is6() && p.Bits() < spfMinIPv6Bits) ||
			!p.Addr().IsGlobalUnicast() || p.Addr().IsPrivate() {
			continue
		}
		out = append(out, p)
	}
	return out
}

// storeSPFRange records a spf_authorizes edge from the apex to the netblock
// (or, for a single address, the IP address) its SPF record authorizes.
func (d *dnsSubs) storeSPFRange(e *et.Event, apex *dbt.Entity, p netip.Prefix) {
	if apex == nil {
		return
	}
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	kind := "IPv4"
	if p.Addr().Is6() {
		kind = "IPv6"
	}
	var asset oam.Asset = &oamnet.Netblock{CIDR: p, Type: kind}
	if p.Bits() == p.Addr().BitLen() {
		asset = &oamnet.IPAddress{Address: p.Addr(), Type: kind}
	}
	to, err := e.Session.DB().CreateAsset(ctx, asset)
	if err != nil || to == nil {
		return
	}
	_, _ = support.Relate(ctx, e.Session, apex, &general.SimpleRelation{Name: relSPFAuthorizes}, to, d.plugin.source)
}

// storeDMARCEdges records a dmarc_reports_to edge from the apex to each domain
// the DMARC record's rua or ruf reporting addresses name.
func (d *dnsSubs) storeDMARCEdges(e *et.Event, apex *dbt.Entity, rr []dns.RR) {
	for _, r := range rr {
		t, ok := r.(*dns.TXT)
		if !ok {
			continue
		}
		for _, domain := range dmarcReportDomains(txtData(t)) {
			d.storeMailPolicyEdge(e, apex, domain, relDMARCReportsTo)
		}
	}
}

// storeMailPolicyEdge creates the target FQDN and the labeled edge from the
// publisher apex to it, with the plugin's source, skipping a self-reference.
func (d *dnsSubs) storeMailPolicyEdge(e *et.Event, from *dbt.Entity, domain, label string) {
	if from == nil || domain == "" {
		return
	}
	if fq, ok := from.Asset.(*oamdns.FQDN); ok && fq != nil && strings.EqualFold(fq.Name, domain) {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	to, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: domain})
	if err != nil || to == nil {
		return
	}

	if _, err := support.Relate(ctx, e.Session, from, &general.SimpleRelation{Name: label}, to, d.plugin.source); err != nil {
		return
	}
	support.MarkAssetMonitored(e.Session, to, d.plugin.source)
}

// spfAuthorizedDomains returns the lowercased domains an SPF record delegates
// its senders to, from its include: and redirect= terms (RFC 7208 sections 5.2
// and 6.1). A mechanism may carry a qualifier (for example "+include:"); macro
// and non-domain values are dropped.
func spfAuthorizedDomains(txt string) []string {
	t := strings.TrimSpace(txt)
	if !strings.HasPrefix(strings.ToLower(t), "v=spf1") {
		return nil
	}

	var out []string
	for _, f := range strings.Fields(t) {
		term := strings.TrimLeft(f, "+-~?")
		low := strings.ToLower(term)
		switch {
		case strings.HasPrefix(low, "include:"):
			out = appendDomain(out, term[len("include:"):])
		case strings.HasPrefix(low, "redirect="):
			out = appendDomain(out, term[len("redirect="):])
		}
	}
	return out
}

// dmarcReportDomains returns the lowercased domains a DMARC record sends reports
// to, from the mailto URIs of its rua and ruf tags (RFC 7489 section 6.3). An
// optional "!size" suffix is dropped; the domain is the part after the "@".
func dmarcReportDomains(txt string) []string {
	t := strings.TrimSpace(txt)
	if !strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
		return nil
	}

	var out []string
	for _, tag := range strings.Split(t, ";") {
		k, v, ok := strings.Cut(tag, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "rua", "ruf":
		default:
			continue
		}
		for _, uri := range strings.Split(v, ",") {
			addr, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(uri)), "mailto:")
			if !ok {
				continue
			}
			addr, _, _ = strings.Cut(addr, "!")
			if _, domain, ok := strings.Cut(addr, "@"); ok {
				out = appendDomain(out, domain)
			}
		}
	}
	return out
}

// appendDomain adds a cleaned domain name to out when it is a plausible domain,
// dropping a trailing dot, an SPF macro, or a value without a dot.
func appendDomain(out []string, s string) []string {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || strings.ContainsAny(s, "%{} ") || !strings.Contains(s, ".") {
		return out
	}
	return append(out, s)
}
