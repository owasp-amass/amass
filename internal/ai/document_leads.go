// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/nyaruka/phonenumbers"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
	oamcontact "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/net/publicsuffix"
)

// documentLead is an asset a document names, as the lead handed to a running
// enumeration, with the selector that finds it in the Asset Database.
type documentLead struct {
	asset    oam.Asset
	selector graph.AssetSelector
	name     string
}

// leadFor returns the lead for an asset of type t a document names, when the
// engine collects from that type. Types the engine has nothing to collect
// from (people, products, places) are kept as statements only. A phone number
// written without a country code is read in region (docmeta.PhoneRegion of
// the document's host).
func leadFor(t, value, region string) (documentLead, bool) {
	value = strings.TrimSpace(value)
	sel := func(field, v string) graph.AssetSelector { return graph.AssetSelector{Type: t, Field: field, Value: v} }
	switch t {
	case "Organization":
		// a unit of the publisher ("Office of Events") or a generic office or
		// service name ("Counseling", "Rapid Response") is kept as a finding:
		// the engine has nothing to look up for it, and the registries match
		// such a name to unrelated bodies
		return documentLead{asset: oamorg.Organization{ID: value, Name: value}, name: value},
			properName(value) && !genericUnit(value) && !semantics.GenericOrganizationName(value)
	case "FQDN":
		name := strings.ToLower(strings.TrimSuffix(value, "."))
		return documentLead{asset: oamdns.FQDN{Name: name}, selector: sel("name", name), name: name},
			domainName.MatchString(name)
	case "IPAddress":
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return documentLead{}, false
		}
		kind := "IPv4"
		if addr.Is6() {
			kind = "IPv6"
		}
		return documentLead{asset: oamnet.IPAddress{Address: addr, Type: kind}, selector: sel("address", addr.String()),
			name: addr.String()}, true
	case "Netblock":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return documentLead{}, false
		}
		prefix = prefix.Masked()
		kind := "IPv4"
		if prefix.Addr().Is6() {
			kind = "IPv6"
		}
		return documentLead{asset: oamnet.Netblock{CIDR: prefix, Type: kind}, selector: sel("cidr", prefix.String()),
			name: prefix.String()}, true
	case "AutonomousSystem":
		n := asNumber(value)
		return documentLead{asset: oamnet.AutonomousSystem{Number: n}, selector: sel("number", strconv.Itoa(n)),
			name: fmt.Sprintf("AS%d", n)}, n > 0
	case "StreetAddress":
		return documentLead{asset: oamcontact.StreetAddress{Address: value}, selector: sel("address", value),
			name: value}, checkValue(t, value) == ""
	case "Phone":
		if strings.HasPrefix(value, "+") {
			region = ""
		}
		num, err := phonenumbers.Parse(value, region)
		if err != nil || !phonenumbers.IsValidNumber(num) {
			return documentLead{}, false
		}
		// the Phone key is Raw, and the engine finds phones by e164, so both
		// hold the E.164 form, as a seeded phone does
		e164 := phonenumbers.Format(num, phonenumbers.E164)
		return documentLead{asset: oamcontact.Phone{Raw: e164, E164: e164}, selector: sel("e164", e164),
			name: e164}, true
	case "Identifier":
		addr := strings.ToLower(value)
		if !emailAddr.MatchString(addr) {
			return documentLead{}, false
		}
		id := oamgen.EmailAddress + ":" + addr
		return documentLead{asset: oamgen.Identifier{UniqueID: id, ID: addr, Type: oamgen.EmailAddress},
			selector: sel("unique_id", id), name: addr}, true
	case "URL":
		// a URL cut from broken markup holds what a real one escapes
		if strings.ContainsAny(value, "<>\"'`{}| \t\r\n") {
			return documentLead{}, false
		}
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return documentLead{}, false
		}
		ou := oamurl.URL{Raw: u.String(), Scheme: u.Scheme, Host: u.Hostname(), Path: u.Path}
		if p := u.Port(); p != "" {
			ou.Port, _ = strconv.Atoi(p)
		} else if u.Scheme == "https" {
			ou.Port = 443
		} else {
			ou.Port = 80
		}
		return documentLead{asset: ou, selector: sel("url", ou.Raw), name: ou.Raw}, true
	}
	return documentLead{}, false
}

// statementLeads returns the leads a stored finding gives: the asset it
// names, both ends of a relation, or the asset an attribute describes.
func statementLeads(s review.StoredStatement, region string) []documentLead {
	var out []documentLead
	add := func(t, v string) {
		if v == lens.DocumentPublisher {
			return
		}
		if l, ok := leadFor(t, v, region); ok {
			out = append(out, l)
		}
	}
	add(s.SubjectType, s.Subject)
	if s.Kind == FindingRelation || (s.Kind == "" && s.ObjectType != "") {
		add(s.ObjectType, s.Object)
	}
	return out
}

// knownLead reports whether the Asset Database holds the lead's asset. A
// lookup that fails counts as known, so an error never submits a lead.
func knownLead(ctx context.Context, g DocumentGraph, l documentLead) bool {
	if _, ok := l.asset.(oamorg.Organization); ok {
		res, err := g.ResolveOrganizations(ctx, graph.OrganizationQuery{Name: l.name}, 2)
		return err != nil || res.Status == "matched" || res.Status == "ambiguous" || res.Status == "truncated"
	}
	res, err := g.ResolveAsset(ctx, l.selector, 1)
	return err != nil || len(res.Candidates) > 0
}

// anchorTypes are the asset types that tie an organization a document names
// to something the engine can look up: a name, a network, an address, a phone,
// an email address or a URL.
var anchorTypes = map[string]bool{"FQDN": true, "URL": true, "IPAddress": true, "Netblock": true,
	"AutonomousSystem": true, "StreetAddress": true, "Phone": true, "Identifier": true}

// anchoredOrganizations returns the organizations a document's findings relate
// to an anchor (an asset of one of anchorTypes), keyed by orgKey.
func anchoredOrganizations(stored []review.StoredStatement) map[string]bool {
	out := make(map[string]bool)
	for _, s := range stored {
		if s.Kind != FindingRelation && (s.Kind != "" || s.ObjectType == "") {
			continue
		}
		switch {
		case s.SubjectType == "Organization" && anchorTypes[s.ObjectType]:
			out[orgKey(s.Subject)] = true
		case s.ObjectType == "Organization" && anchorTypes[s.SubjectType]:
			out[orgKey(s.Object)] = true
		}
	}
	return out
}

// anchoredLead reports whether a lead has an anchor: any lead but an
// organization is one, and an organization has one when the document ties it
// to one. Only leads with an anchor go to the engine: a name alone gives it
// only the registries to search, where it matches nothing or the wrong body
// as often as not.
func anchoredLead(l documentLead, anchored map[string]bool) bool {
	if _, ok := l.asset.(oamorg.Organization); !ok {
		return true
	}
	return anchored[orgKey(l.name)]
}

// orgKey folds an organization name for comparison.
func orgKey(name string) string {
	return strings.ToLower(strings.Join(strings.Fields(name), " "))
}

// targetLabels returns the labels of a run's target domains before their
// public suffix ("owasp" for owasp.org, "acme" for acme.co.uk), lower-cased.
func targetLabels(run collect.Run) map[string]bool {
	out := map[string]bool{}
	for _, d := range documentTargets(run) {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		apex, err := publicsuffix.EffectiveTLDPlusOne(d)
		if err != nil {
			continue
		}
		suffix, _ := publicsuffix.PublicSuffix(apex)
		if label := strings.TrimSuffix(strings.TrimSuffix(apex, suffix), "."); label != "" {
			out[label] = true
		}
	}
	return out
}

// selfReference reports whether an organization lead is the run's own target
// written as its domain label or acronym ("OWASP" in owasp.org's documents):
// the organization the run is already about, which the registries would only
// confuse with others of the same initials.
func selfReference(l documentLead, labels map[string]bool) bool {
	if _, ok := l.asset.(oamorg.Organization); !ok || len(labels) == 0 {
		return false
	}
	var b strings.Builder
	for _, r := range strings.ToLower(l.name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return labels[b.String()]
}

// unitPrefixes start the names of an organization's own units.
var unitPrefixes = []string{"office of ", "department of ", "dept. of ", "division of ", "school of ",
	"center for ", "centre for ", "college of ", "program in ", "programs in "}

// publicMarkers mark a unit-like name as a public body the registries know
// ("Department of State", "Federal Office of …"), not a unit of the
// document's publisher.
var publicMarkers = []string{"federal", "national", "united states", "u.s.", "state", "county", "city of",
	"government"}

// genericUnit reports whether an organization name is a generic unit of the
// document's publisher: a unit prefix followed by at most three words, with no
// mark of a public body. It is a heuristic: a short unit-like name of a real
// outside body without such a mark ("Office of Personnel Management") is
// still kept as a finding, just not sent to the engine.
func genericUnit(name string) bool {
	lower := strings.ToLower(strings.Join(strings.Fields(name), " "))
	for _, m := range publicMarkers {
		if strings.Contains(lower, m) {
			return false
		}
	}
	for _, p := range unitPrefixes {
		if rest, ok := strings.CutPrefix(lower, p); ok {
			return len(strings.Fields(rest)) <= 3
		}
	}
	return false
}
