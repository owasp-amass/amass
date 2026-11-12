// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed semantics/txt_vendors.json
var txtVendorsJSON []byte

type spfSender struct {
	Vendor  string   `json:"vendor"`
	Domains []string `json:"domains"`
	Source  string   `json:"source"`
}

type txtVendorRules struct {
	License             string      `json:"_license"`
	About               string      `json:"_about"`
	VerificationMarkers []string    `json:"verification_markers"`
	SPFSenders          []spfSender `json:"spf_senders"`
}

var loadTXTVendors = sync.OnceValue(func() txtVendorRules {
	var r txtVendorRules
	if err := decodeStrict(txtVendorsJSON, &r); err != nil {
		panic("txt_vendors.json: " + err.Error())
	}
	if err := validateTXTVendors(r); err != nil {
		panic("txt_vendors.json: " + err.Error())
	}

	return r
})

func validateTXTVendors(r txtVendorRules) error {
	if len(r.VerificationMarkers) == 0 {
		return errors.New("verification_markers required")
	}
	for _, s := range r.SPFSenders {
		switch {
		case s.Vendor == "" || len(s.Domains) == 0:
			return fmt.Errorf("spf sender %q: vendor and domains are required", s.Vendor)
		case !strings.HasPrefix(s.Source, "https://"):
			// Every entry must be checkable against the vendor's own documentation.
			return fmt.Errorf("spf sender %s: source must cite the vendor's documentation", s.Vendor)
		}
		for _, d := range s.Domains {
			if d == "" || d != strings.ToLower(d) || strings.HasSuffix(d, ".") {
				return fmt.Errorf("spf sender %s: domain %q must be lower case without a trailing dot", s.Vendor, d)
			}
		}
	}

	return nil
}

// Vendor kinds found in TXT records and their verified_for relationships.
const (
	kindVerification = "SaaS: domain verification (DNS TXT)"
	kindSPF          = "Email: authorized senders (SPF)"
)

// verifiedForLabel is the relationship the DNS-SD plugin stores from a
// domain to the organization behind a verification token it recognizes.
const verifiedForLabel = "verified_for"

// txtValues returns the TXT record values stored for an asset.
func txtValues(ctx context.Context, graph Graph, id string) ([]string, error) {
	evidence, err := graph.Evidence(ctx, id, 100)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, e := range evidence {
		data, err := json.Marshal(e.Property)
		if err != nil {
			continue
		}

		var p struct {
			Name   string `json:"property_name"`
			Header struct {
				RRType int `json:"rr_type"`
			} `json:"header"`
			Data string `json:"data"`
		}
		if json.Unmarshal(data, &p) == nil && p.Name == dnsRecordProperty && p.Header.RRType == rrTypeTXT &&
			p.Data != "" {
			out = append(out, strings.Trim(p.Data, `"`))
		}
	}

	return out, nil
}

// txtScan is what a domain's TXT records show: the SPF senders a vendor
// entry recognizes, the SPF includes none does, and the records that look
// like a service's verification token.
type txtScan struct {
	senders    []VendorUse
	unknownSPF []string
	tokens     []string
}

// scanTXT reads a domain's TXT records. An SPF include of the domain's own
// registrable domain is the domain itself, not a vendor.
func scanTXT(records []string, domain string) txtScan {
	rules := loadTXTVendors()
	own := registeredDomain(domain)
	found := map[string]*VendorUse{}
	unknown := map[string]bool{}
	var scan txtScan

	for _, rec := range records {
		rec = strings.TrimSpace(rec)
		lower := strings.ToLower(rec)
		if verificationLike(lower, rules.VerificationMarkers) {
			scan.tokens = append(scan.tokens, rec)
		}
		if !strings.HasPrefix(lower, "v=spf1") {
			continue
		}

		for _, target := range spfTargets(lower) {
			sender, ok := spfSenderOf(rules.SPFSenders, target)
			switch {
			case ok:
				key := sender.Vendor
				if _, seen := found[key]; !seen {
					found[key] = &VendorUse{Vendor: sender.Vendor, Kind: kindSPF, Via: "SPF include:" + target,
						Assets: 1, Examples: []string{domain}}
				}
			case registeredDomain(target) != own:
				unknown[target] = true
			}
		}
	}

	for _, v := range found {
		scan.senders = append(scan.senders, *v)
	}
	sort.Slice(scan.senders, func(i, j int) bool { return scan.senders[i].Vendor < scan.senders[j].Vendor })
	for t := range unknown {
		scan.unknownSPF = append(scan.unknownSPF, t)
	}
	sort.Strings(scan.unknownSPF)

	return scan
}

// spfTargets returns the domains named by a v=spf1 record's include: and
// redirect= mechanisms, with any qualifier and trailing dot removed.
func spfTargets(record string) []string {
	var out []string
	for _, mech := range strings.Fields(record) {
		mech = strings.TrimLeft(mech, "+?~-")
		target := ""
		switch {
		case strings.HasPrefix(mech, "include:"):
			target = strings.TrimPrefix(mech, "include:")
		case strings.HasPrefix(mech, "redirect="):
			target = strings.TrimPrefix(mech, "redirect=")
		default:
			continue
		}
		if target = strings.TrimSuffix(target, "."); target != "" {
			out = append(out, target)
		}
	}

	return out
}

// spfSenderOf finds the vendor entry whose domain is target, a parent of
// it, or has target as its registrable domain: customers often publish the
// vendor's own domain (include:service-now.com) rather than the documented
// one (_spfinc1.service-now.com), and it still names the vendor.
func spfSenderOf(senders []spfSender, target string) (spfSender, bool) {
	for _, s := range senders {
		for _, d := range s.Domains {
			if target == d || strings.HasSuffix(target, "."+d) || target == registeredDomain(d) {
				return s, true
			}
		}
	}

	return spfSender{}, false
}

// verificationLike reports whether a lower-cased TXT record looks like a
// service's verification token: a short key, before the first '=' or ':',
// that contains one of the markers.
func verificationLike(record string, markers []string) bool {
	key, ok := tokenKey(record)
	if !ok {
		return false
	}
	for _, m := range markers {
		if strings.Contains(key, m) {
			return true
		}
	}

	return false
}

// tokenKey returns the text of a TXT record before its first '=' or ':',
// with the separator, when it is short and has no spaces.
func tokenKey(record string) (string, bool) {
	i := strings.IndexAny(record, "=:")
	if i < 1 || i > 64 || strings.ContainsAny(record[:i], " \t") {
		return "", false
	}

	return record[:i+1], true
}

// VendorOptions adjust the vendors lens.
type VendorOptions struct {
	// KnownVerification reports whether a TXT record is a verification token
	// the DNS-SD plugin recognizes. Records it rejects are reported as
	// unrecognized; when nil, every verification-like record is.
	KnownVerification func(record string) bool
	// Limits bound the third-party walk; zero values use the defaults.
	Limits LensLimits
}

// FindVendors lists the outside parties a domain and its organization's
// controlled assets depend on: the third-party lens over stored
// relationships, the organizations the domain's verification tokens name,
// and the mail senders its SPF record authorizes. It also reports the SPF
// includes and verification-like records nothing recognizes. root is the
// domain's FQDN. It reads only.
func FindVendors(ctx context.Context, graph Graph, schema SchemaCatalog, root Asset,
	opts VendorOptions) (ThirdPartyReport, error) {
	if root.Type != "FQDN" {
		return ThirdPartyReport{}, errors.New("the vendors lens starts from a domain name")
	}

	r, err := searchThirdPartiesWithin(ctx, graph, schema, root, opts.Limits)
	if err != nil {
		return r, err
	}

	if family, err := FindOrganizationFamily(ctx, graph, root); err != nil {
		r.FamilyNote = fmt.Sprintf("The family lens could not run (%v), so the institution's own organizations may "+
			"be listed as vendors.", err)
	} else {
		applyFamily(&r, family)
	}

	verified, err := verifiedFor(ctx, graph, root)
	if err != nil {
		return r, fmt.Errorf("verification relationships of %s: %w", assetLabel(root), err)
	}
	r.Vendors = mergeVerified(r.Vendors, verified)

	records, err := txtValues(ctx, graph, root.ID)
	if err != nil {
		return r, fmt.Errorf("TXT records of %s: %w", assetLabel(root), err)
	}

	scan := scanTXT(records, fqdnName(root))
	r.Vendors = append(r.Vendors, scan.senders...)
	r.UnrecognizedSPF = scan.unknownSPF
	keys := map[string]bool{}
	for _, rec := range scan.tokens {
		if opts.KnownVerification != nil && opts.KnownVerification(rec) {
			continue
		}
		if key, ok := tokenKey(strings.ToLower(rec)); ok && !keys[key] {
			keys[key] = true
			r.UnrecognizedTokens = append(r.UnrecognizedTokens, key)
		}
	}
	sort.Strings(r.UnrecognizedTokens)

	return r, nil
}

// verifiedFor returns the organizations the root's verified_for
// relationships name. They are read by label, so they are found even when
// the domain has more relationships than the lens reads.
func verifiedFor(ctx context.Context, graph Graph, root Asset) ([]VendorUse, error) {
	edges, err := graph.Edges(ctx, root.ID, "out", verifiedForLabel, time.Time{})
	if err != nil {
		return nil, err
	}

	byName := map[string]*VendorUse{}
	var order []string
	for _, e := range edges {
		org, err := graph.GetAsset(ctx, e.ToID)
		if err != nil {
			return nil, err
		}

		name := assetLabel(org)
		key := strings.ToLower(name)
		if name == "" || byName[key] != nil {
			continue
		}

		byName[key] = &VendorUse{Vendor: name, VendorID: org.ID, Kind: kindVerification,
			Via: "FQDN " + verifiedForLabel, Assets: 1, Examples: []string{assetLabel(root)},
			Witness: []WitnessEdge{witnessOf(e, root, org)}}
		order = append(order, key)
	}

	out := make([]VendorUse, 0, len(order))
	for _, k := range order {
		out = append(out, *byName[k])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })

	return out, nil
}

// mergeVerified files the lens's verified_for findings under the
// verification kind, and adds the root's own verified_for organizations the
// lens did not reach.
func mergeVerified(vendors, verified []VendorUse) []VendorUse {
	have := map[string]bool{}
	for i := range vendors {
		if vendors[i].Via == "FQDN "+verifiedForLabel {
			vendors[i].Kind = kindVerification
			have[strings.ToLower(vendors[i].Vendor)] = true
		}
	}
	for _, v := range verified {
		if !have[strings.ToLower(v.Vendor)] {
			vendors = append(vendors, v)
		}
	}

	return vendors
}

// FormatVendorReport renders a vendors report for a terminal.
func FormatVendorReport(r ThirdPartyReport) string {
	var b strings.Builder
	b.WriteString(thirdPartyAnswer(groupVendorKinds(r)))
	b.WriteString("\n")
	switch r.Reason {
	case "controlled asset limit":
		b.WriteString("Raise -max-assets to follow more of the controlled assets.\n")
	case "database read limit":
		b.WriteString("Raise -max-reads to read more of the database.\n")
	}
	b.WriteString(familyLines(r))
	if len(r.UnrecognizedSPF) > 0 {
		fmt.Fprintf(&b, "\nSPF includes no vendor entry recognizes (%d): %s\n", len(r.UnrecognizedSPF),
			strings.Join(r.UnrecognizedSPF, ", "))
	}
	if len(r.UnrecognizedTokens) > 0 {
		fmt.Fprintf(&b, "\nVerification-like TXT records no DNS-SD prefix recognizes (%d): %s\n",
			len(r.UnrecognizedTokens), strings.Join(r.UnrecognizedTokens, ", "))
	}
	if len(r.UnrecognizedSPF)+len(r.UnrecognizedTokens) > 0 {
		b.WriteString("Confirm each against the vendor's documentation before adding it to " +
			"internal/ai/semantics/txt_vendors.json or the DNS-SD verification prefixes.\n")
	}

	return b.String()
}

// groupVendorKinds orders the report's vendors so each kind is listed once,
// after FindVendors has added kinds the lens's own sort did not see.
func groupVendorKinds(r ThirdPartyReport) ThirdPartyReport {
	first := map[string]int{}
	for i, v := range r.Vendors {
		if _, ok := first[v.Kind]; !ok {
			first[v.Kind] = i
		}
	}

	vendors := append([]VendorUse(nil), r.Vendors...)
	sort.SliceStable(vendors, func(i, j int) bool { return first[vendors[i].Kind] < first[vendors[j].Kind] })
	r.Vendors = vendors
	return r
}
