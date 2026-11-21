// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"context"
	"log/slog"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/product"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/docmeta"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/net/publicsuffix"
)

// maxLeads caps the leads of one kind taken from one document, so a
// directory or a log dump cannot flood the session.
const maxLeads = 500

// leads tallies what a document contributed, for its log line.
type leads struct {
	people, orgs, products, accounts, names, urls, emails, addrs, phones int
}

// author is a person the document's metadata names, with the name parts a
// username is compared with.
type author struct {
	ent         *dbt.Entity
	first, last string
}

// metadataLeads stores what the document's metadata names as OAM assets
// linked from the File: the people who wrote or last edited it and the
// organization named as its company (author), and the software that made it
// (created_with). Each is dispatched as a lead.
func (d *documents) metadataLeads(e *et.Event, fent *dbt.Entity, meta docmeta.Metadata, n *leads) []author {
	rules := semantics.Documents()

	var authors []author
	seen := map[string]bool{}
	for _, raw := range []string{meta.Author, meta.LastModifiedBy} {
		raw = strings.TrimSpace(raw)
		if raw == "" || rules.IsPlaceholderAuthor(raw) || seen[strings.ToLower(raw)] {
			continue
		}
		seen[strings.ToLower(raw)] = true

		p := support.FullNameToPerson(raw)
		if p == nil {
			continue
		}
		if pent, err := support.CreatePersonAsset(e.Session, fent, rel("author"), p, d.source); err == nil {
			d.dispatch(e, pent, p.FullName)
			authors = append(authors, author{ent: pent, first: p.FirstName, last: p.FamilyName})
			n.people++
		}
	}

	var vendors []string
	madeWith := map[string]bool{}
	for _, raw := range []string{meta.Creator, meta.Producer} {
		sw, version, ok := semantics.MatchDocumentSoftware(raw)
		if !ok || madeWith[sw.CPE+" "+version] {
			continue
		}
		madeWith[sw.CPE+" "+version] = true
		vendors = append(vendors, sw.Vendor)

		res, err := product.CreateProductAsset(e.Session, fent, rel("created_with"), product.Software{
			CPE:      sw.CPE,
			Name:     sw.Name,
			Vendor:   sw.Vendor,
			Category: sw.Category,
			Version:  version,
		}, d.source)
		if err != nil || res == nil {
			continue
		}
		n.products++
		for _, ent := range []*dbt.Entity{res.Product, res.Release, res.Manufacturer} {
			if ent != nil {
				d.dispatch(e, ent, ent.Asset.Key())
			}
		}
	}

	if company := strings.TrimSpace(meta.Company); companyNamesAuthor(rules, company, vendors) {
		if oent, err := org.CreateOrgAsset(e.Session, fent, rel("author"),
			&oamorg.Organization{Name: company}, d.source); err == nil && oent != nil {
			d.dispatch(e, oent, company)
			n.orgs++
		}
	}
	return authors
}

// companyNamesAuthor reports whether a Company value names the author's
// organization: not empty, not a preset or default value, not a redaction
// placeholder, and not the vendor of the software that made the document
// (an unregistered copy of Office reports "Microsoft").
func companyNamesAuthor(rules semantics.DocumentRules, company string, vendors []string) bool {
	if company == "" || rules.IsPlaceholderCompany(company) || semantics.IsPlaceholderOrganization(company) {
		return false
	}

	brand := org.ExtractBrandName(strings.ToLower(company))
	for _, v := range vendors {
		if vb := org.ExtractBrandName(strings.ToLower(v)); brand == vb || strings.HasPrefix(vb, brand+" ") {
			return false
		}
	}
	return true
}

// contentLeads reads the document's text and links and stores what they name
// as OAM assets linked from the File by contains: web URLs, host names,
// email addresses, IP addresses and phone numbers. In-scope URLs, names and
// addresses, every email address the scope accepts, and every phone number
// are dispatched as leads for the enumeration to validate; an out-of-scope
// URL or name is recorded as what the document references (a vendor, a
// partner) without being enumerated.
//
// It returns the usernames the text shows in home-directory paths, for the
// account leads.
func (d *documents) contentLeads(e *et.Event, fent *dbt.Entity, u *oamurl.URL, dt semantics.DocumentType,
	data []byte, n *leads) []string {
	content, err := docmeta.ExtractContent(dt.Format, data)
	if err != nil {
		return nil
	}

	body := content.Text + "\n" + strings.Join(content.Links, "\n")
	static := semantics.ArchiveURLs()

	hosts := map[string]bool{}
	var urls []*oamurl.URL
	seenURL := map[string]bool{}
	addURL := func(x *oamurl.URL) {
		if x == nil || x.Host == "" || seenURL[x.Raw] || len(urls) >= maxLeads || static.IsStaticPath(x.Path) {
			return
		}
		seenURL[x.Raw] = true
		urls = append(urls, x)
		hosts[strings.ToLower(x.Host)] = true
	}
	for _, link := range content.Links {
		addURL(support.RawURLToOAM(link))
	}
	// a URL written without a scheme ("portal.example.edu/login") is taken
	// only when in scope: out of scope, the relaxed pattern also matches
	// abbreviations, file names and noise ("k.bs"), so an out-of-scope URL
	// must be written as one (http:// or https://)
	explicit := map[string]bool{}
	for _, m := range explicitURLRe.FindAllString(content.Text, -1) {
		if x := support.RawURLToOAM(strings.TrimRight(m, ".,;:")); x != nil && x.Host != "" {
			explicit[strings.ToLower(x.Host)] = true
		}
	}
	for _, x := range support.ExtractURLsFromString(content.Text) {
		if explicit[strings.ToLower(x.Host)] || inScope(e, x.Host) {
			addURL(x)
		}
	}
	for _, x := range urls {
		if ent := d.linkAsset(e, fent, x); ent != nil {
			n.urls++
			if inScope(e, x.Host) {
				d.dispatch(e, ent, x.Raw)
			}
		}
	}

	var emails []string
	for _, addr := range support.ExtractEmailsFromString(body) {
		if len(emails) >= maxLeads {
			break
		}
		emails = append(emails, addr)
		if _, domain, ok := strings.Cut(addr, "@"); ok {
			hosts[strings.ToLower(domain)] = true
		}
	}
	if ents := support.StoreEmailsWithSource(e.Session, emails, d.source, d.name, d.name+"-Handler"); len(ents) > 0 {
		for _, ent := range ents {
			d.contains(e, fent, ent)
		}
		n.emails += len(ents)
		// dispatches only the addresses the scope accepts
		support.ProcessEmailsWithSource(e, ents, d.source)
	}

	// a bare name is taken when it is in scope, or when it is the host of a
	// URL or email address above: a word that merely looks like a name
	// ("readme.md") is not a lead
	var names []string
	for _, m := range amassdns.AnySubdomainRegex().FindAllString(body, -1) {
		name := strings.ToLower(strings.Trim(m, "."))
		if hosts[name] || inScope(e, name) {
			if isDomainName(name) {
				hosts[name] = true
			}
		}
	}
	for name := range hosts {
		if isDomainName(name) && len(names) < maxLeads {
			names = append(names, name)
		}
	}
	for _, ent := range support.StoreFQDNsWithSource(e.Session, names, d.source, d.name, d.name+"-Handler") {
		d.contains(e, fent, ent)
		n.names++
		if fqdn, ok := ent.Asset.(*oamdns.FQDN); ok && inScope(e, fqdn.Name) {
			d.dispatch(e, ent, fqdn.Name)
		}
	}

	for _, addr := range ipAddresses(body) {
		ip := &oamnet.IPAddress{Address: addr, Type: "IPv4"}
		if addr.Is6() {
			ip.Type = "IPv6"
		}
		if ent := d.linkAsset(e, fent, ip); ent != nil {
			n.addrs++
			if _, conf := e.Session.Scope().IsAssetInScope(ip, 0); conf > 0 {
				d.dispatch(e, ent, addr.String())
			}
		}
	}

	for _, ph := range phoneNumbers(body, regionOf(u.Host)) {
		if ent := d.linkAsset(e, fent, ph); ent != nil {
			n.phones++
			d.dispatch(e, ent, ph.E164)
		}
	}

	return docmeta.Usernames(content.Text)
}

// explicitURLRe finds URLs written with their web scheme.
var explicitURLRe = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"'()\[\]{}]+`)

// isDomainName reports whether name ends in a public suffix ICANN manages
// and has a label in front of it.
func isDomainName(name string) bool {
	if addr, err := netip.ParseAddr(name); err == nil && addr.IsValid() {
		return false
	}
	suffix, icann := publicsuffix.PublicSuffix(name)
	return icann && suffix != name && strings.Contains(name, ".")
}

// ipv4Re finds dotted-quad IPv4 addresses.
var ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// ipAddresses returns the globally routable IPv4 addresses in s. Private,
// loopback and other special-purpose addresses are left out: the same
// 10.0.0.1 appears in every organization's documents, so it would link
// unrelated targets to one asset.
func ipAddresses(s string) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, m := range ipv4Re.FindAllString(s, -1) {
		addr, err := netip.ParseAddr(m)
		if err != nil || seen[addr] || !addr.IsGlobalUnicast() || addr.IsPrivate() {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
		if len(out) >= maxLeads {
			break
		}
	}
	return out
}

// phoneRe finds phone numbers written as phone numbers: an international
// number with a leading "+", or a North American number in its usual
// groupings. Bare digit runs (IDs, dates, amounts) are not taken.
var phoneRe = regexp.MustCompile(`\+\d{1,3}(?:[\s.-]?\(?\d{1,4}\)?){2,5}\d|` +
	`(?:\b1[\s.-])?\(?\b\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b`)

// phoneNumbers returns the valid phone numbers in s; a number without a
// country code is read in region.
func phoneNumbers(s, region string) []*oamcon.Phone {
	var out []*oamcon.Phone
	seen := map[string]bool{}
	for _, m := range phoneRe.FindAllString(s, -1) {
		r := region
		if strings.HasPrefix(m, "+") {
			r = ""
		}
		ph := support.PhoneToOAMPhone(m, "", r)
		if ph == nil || seen[ph.E164] {
			continue
		}
		seen[ph.E164] = true
		out = append(out, ph)
		if len(out) >= maxLeads {
			break
		}
	}
	return out
}

// regionOf is the region a document's national phone numbers are read in:
// the country of its host's country-code domain, otherwise US (where the
// North American groupings phoneRe accepts are used).
func regionOf(host string) string {
	if i := strings.LastIndexByte(host, '.'); i >= 0 {
		if tld := strings.ToUpper(host[i+1:]); len(tld) == 2 {
			if tld == "UK" {
				return "GB"
			}
			return tld
		}
	}
	return "US"
}

func rel(name string) oam.Relation { return &oamgen.SimpleRelation{Name: name} }

// linkAsset stores a, records the document as a source of it, and links the
// File to it by contains.
func (d *documents) linkAsset(e *et.Event, fent *dbt.Entity, a oam.Asset) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	ent, err := e.Session.DB().CreateAsset(ctx, a)
	if err != nil || ent == nil {
		return nil
	}
	d.sourced(ctx, e, ent)
	d.contains(e, fent, ent)
	return ent
}

// contains links the File to what it mentions.
func (d *documents) contains(e *et.Event, fent, ent *dbt.Entity) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel("contains"), FromEntity: fent, ToEntity: ent})
	if err != nil || edge == nil {
		return
	}
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
		Source:     d.source.Name,
		Confidence: d.source.Confidence,
	})
}

// dispatch hands an asset to the pipeline as a lead.
func (d *documents) dispatch(e *et.Event, ent *dbt.Entity, name string) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{Name: name, Entity: ent, Session: e.Session})
}

// logLeads records what one document contributed.
func (d *documents) logLeads(e *et.Event, u *oamurl.URL, n leads) {
	e.Session.Log().Info("document leads", "url", u.Raw, "people", n.people, "organizations", n.orgs,
		"products", n.products, "accounts", n.accounts, "names", n.names, "urls", n.urls, "emails", n.emails, "addresses", n.addrs,
		"phones", n.phones, slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
}
