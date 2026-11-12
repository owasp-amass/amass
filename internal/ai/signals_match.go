// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

// ValueSearcher finds the other assets that carry a value one asset has,
// such as the same DNS TXT verification token or certificate key
// identifier. Searches are bounded; more reports that further matches exist.
type ValueSearcher interface {
	// FindByTagValue finds assets of assetType with a stored property named
	// name whose value equals value, or contains it (case-insensitive) when
	// contains is set.
	FindByTagValue(ctx context.Context, assetType, name, value string, contains bool, limit int) ([]Asset, bool, error)
	// FindByAttribute finds assets of assetType whose stored attribute key
	// equals value, or whose text contains it (case-insensitive) when
	// contains is set.
	FindByAttribute(ctx context.Context, assetType, key, value string, contains bool, limit int) ([]Asset, bool, error)
}

// ErrValueSearchUnsupported reports a repository without value searches;
// the signals that need them are skipped.
var ErrValueSearchUnsupported = errors.New("the repository does not support value searches")

// Value signal bounds.
const (
	// gapMaxValueReads bounds the value searches and tag reads of one run.
	gapMaxValueReads = 120
	// gapMaxReferencing bounds the TXT records read for one domain name.
	gapMaxReferencing = 100
	// dnsRecordProperty is the property name of stored DNS records.
	dnsRecordProperty = "dns_record"
	rrTypeNS          = 2
	rrTypeMX          = 15
	rrTypeTXT         = 16
)

// relationRRType returns the DNS record type a stored relation carries, or 0.
func relationRRType(e Relation) int {
	data, err := json.Marshal(e.Content)
	if err != nil {
		return 0
	}

	var f struct {
		Header struct {
			RRType int `json:"rr_type"`
		} `json:"header"`
	}
	if json.Unmarshal(data, &f) != nil {
		return 0
	}

	return f.Header.RRType
}

func rrTypeName(rr int) string {
	switch rr {
	case rrTypeNS:
		return "NS"
	case rrTypeMX:
		return "MX"
	}

	return ""
}

// selfHostedDNS reports whether s, seen from a controlled asset, makes the
// other end's name or mail servers one of the subject's own hosts: an NS or
// MX record, or a registered name server, pointing at it.
func (g *gapSearch) selfHostedDNS(s step) bool {
	for _, def := range signalsByMatcher(matchDNSIntoFootprint) {
		if slices.Contains(def.Params.Labels, s.edge.Label) {
			return true
		}
		if s.attr == attrInfrastructure && slices.Contains(def.Params.RRTypes, relationRRType(s.edge)) {
			return true
		}
	}

	return false
}

// valueSignals finds the signals that need value searches: TXT verification
// tokens and email authentication references for the subject's apex
// domains, and certificate key matches for its certificates. They are
// skipped when the repository cannot search by value.
func (g *gapSearch) valueSignals(order []string) error {
	vs, ok := g.w.graph.(ValueSearcher)
	if !ok {
		return nil
	}

	g.values = vs
	// The strong and DNS signals run first, so the tiebreaker cannot use up
	// the value-search budget they need.
	for pass := 0; pass < 2; pass++ {
		for _, id := range order {
			if err := g.w.ctx.Err(); err != nil {
				return err
			}
			if g.valueReads >= gapMaxValueReads || g.w.report.Reads >= g.w.maxReads {
				g.w.truncate("value search limit")
				return nil
			}

			err := g.valueSignalsOf(g.owned[id], pass)
			if errors.Is(err, ErrValueSearchUnsupported) {
				return nil
			} else if err != nil {
				return err
			}
		}
	}

	return nil
}

// valueSignalsOf runs the value signals one controlled asset gives in a
// pass: verification tokens, email authentication and redirects for apex
// domains, key matches for certificates and provider accounts for domain
// registrations first, then the fingerprints (JARM, page titles, analytics
// identifiers, content and favicon hashes) of controlled names, addresses
// and URLs.
func (g *gapSearch) valueSignalsOf(a Asset, pass int) error {
	if pass == 1 {
		switch a.Type {
		case "FQDN", "IPAddress", "URL":
			return g.fingerprintSignals(a)
		}

		return nil
	}

	switch a.Type {
	case "FQDN":
		if g.isApex(a) {
			if err := g.txtSignals(a); err != nil {
				return err
			}

			return g.redirectSignals(a)
		}
	case "TLSCertificate":
		return g.certificateSignals(a)
	case "DomainRecord":
		return g.nameserverSignals(a)
	}

	return nil
}

// read counts one value search or tag read against the run's budgets.
func (g *gapSearch) read() bool {
	if g.valueReads >= gapMaxValueReads || g.w.report.Reads >= g.w.maxReads {
		return false
	}

	g.valueReads++
	g.w.report.Reads++
	return true
}

// isApex reports whether a controlled name is a registered domain: it has
// a registration record.
func (g *gapSearch) isApex(a Asset) bool {
	steps, err := g.w.steps(a)
	if err != nil {
		return false
	}
	for _, s := range steps {
		if s.forward && s.edge.Label == "registration" {
			return true
		}
	}

	return false
}

// txtRecords returns the TXT record values stored for an asset.
func (g *gapSearch) txtRecords(a Asset) ([]string, error) {
	if !g.read() {
		return nil, nil
	}

	return txtValues(g.w.ctx, g.w.graph, a.ID)
}

// matched is a witness for two assets that carry the same value. It is
// derived from stored values, not a stored relationship, so it has no edge
// ID.
func matched(from, to Asset, label, detail string) WitnessEdge {
	return WitnessEdge{Label: label, RelationType: "MatchedValue", FromID: from.ID, FromType: from.Type,
		From: assetLabel(from), ToID: to.ID, ToType: to.Type, To: assetLabel(to), Detail: detail}
}

// txtSignals finds the domains that share a verification token with apex,
// and the domains whose SPF or DMARC records delegate to it.
func (g *gapSearch) txtSignals(apex Asset) error {
	records, err := g.txtRecords(apex)
	if err != nil {
		return err
	}
	for _, def := range signalsByMatcher(matchTXTToken) {
		for _, txt := range records {
			prefix := verificationPrefix(txt, def.Params.TXTPrefixes)
			if prefix == "" || !g.read() {
				continue
			}

			others, more, err := g.values.FindByTagValue(g.w.ctx, "FQDN", dnsRecordProperty, txt, false, gapMaxShared+1)
			if err != nil {
				return err
			}
			if more || len(others) > gapMaxShared {
				continue
			}
			for _, o := range others {
				witness := append(g.pathTo(apex.ID), matched(apex, o, "same_txt_token", prefix))
				g.add(o, def.ID, "FQDN TXT "+strings.TrimSuffix(prefix, "="), witness)
			}
		}
	}

	return g.referenceSignals(apex)
}

// verificationPrefix returns the verification prefix txt starts with.
func verificationPrefix(txt string, prefixes []string) string {
	lower := strings.ToLower(strings.TrimSpace(txt))
	for _, p := range prefixes {
		if p = strings.ToLower(p); strings.HasPrefix(lower, p) && len(lower) > len(p) {
			return p
		}
	}

	return ""
}

// referenceSignals finds the domains whose SPF record includes or
// redirects to apex (or a name below it), or whose DMARC record sends
// reports to an address there.
func (g *gapSearch) referenceSignals(apex Asset) error {
	defs := signalsByMatcher(matchTXTReference)
	name := strings.ToLower(assetLabel(apex))
	if len(defs) == 0 || name == "" || !g.read() {
		return nil
	}

	found, _, err := g.values.FindByTagValue(g.w.ctx, "FQDN", dnsRecordProperty, name, true, gapMaxReferencing)
	if err != nil {
		return err
	}
	for _, f := range found {
		if _, mine := g.owned[f.ID]; mine {
			continue
		}

		records, err := g.txtRecords(f)
		if err != nil {
			return err
		}
		for _, txt := range records {
			term := delegatesTo(txt, name)
			if term == "" {
				continue
			}

			candidate := g.dmarcDomain(f)
			for _, def := range defs {
				witness := append(g.pathTo(apex.ID), matched(f, apex, "txt_reference", term))
				g.add(candidate, def.ID, "FQDN "+strings.SplitN(term, ":", 2)[0]+" FQDN", witness)
			}
		}
	}

	return nil
}

// delegatesTo returns the SPF or DMARC term in txt that delegates to domain
// or a name below it ("include:_spf.example.com", "rua:example.com"), or "".
func delegatesTo(txt, domain string) string {
	lower := strings.ToLower(strings.TrimSpace(txt))
	within := func(host string) bool { return hostWithin(host, domain) }

	switch {
	case strings.HasPrefix(lower, "v=spf1"):
		for _, term := range strings.Fields(lower) {
			term = strings.TrimLeft(term, "+?~")
			for _, mech := range []string{"include:", "redirect="} {
				if host, ok := strings.CutPrefix(term, mech); ok && within(host) {
					return strings.TrimRight(mech, ":=") + ":" + host
				}
			}
		}
	case strings.HasPrefix(lower, "v=dmarc1"):
		for _, tag := range strings.Split(lower, ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(tag), "=")
			if !ok || (key != "rua" && key != "ruf") {
				continue
			}
			for _, uri := range strings.Split(value, ",") {
				addr := strings.TrimPrefix(strings.TrimSpace(uri), "mailto:")
				if _, host, ok := strings.Cut(addr, "@"); ok {
					host, _, _ = strings.Cut(host, "!")
					if within(host) {
						return key + ":" + host
					}
				}
			}
		}
	}

	return ""
}

// dmarcDomain returns the domain a DMARC record name (_dmarc.example.org)
// belongs to, when it is stored, and the name itself otherwise.
func (g *gapSearch) dmarcDomain(f Asset) Asset {
	if !strings.HasPrefix(strings.ToLower(assetLabel(f)), "_dmarc.") {
		return f
	}

	steps, err := g.w.steps(f)
	if err != nil {
		return f
	}
	for _, s := range steps {
		if !s.forward && s.edge.Label == "node" && s.other.Type == "FQDN" {
			return s.other
		}
	}

	return f
}

// certificateSignals finds certificates that share a key identifier with a
// controlled certificate; the candidate is the name each was issued to.
func (g *gapSearch) certificateSignals(cert Asset) error {
	for _, def := range signalsByMatcher(matchCertificateField) {
		value := contentString(cert, def.Params.Attribute)
		if value == "" || !g.read() {
			continue
		}
		if len(def.Params.PublicIssuers) > 0 {
			// The issuing key must belong to a private CA: its chain is stored
			// and names no public certificate authority.
			private, err := g.privateChain(cert, def.Params.PublicIssuers)
			if err != nil {
				return err
			}
			if !private {
				continue
			}
		}

		others, more, err := g.values.FindByAttribute(g.w.ctx, "TLSCertificate", def.Params.Attribute, value, false,
			gapMaxShared+1)
		if err != nil {
			return err
		}
		if more || len(others) > gapMaxShared {
			continue
		}
		for _, o := range others {
			if o.ID == cert.ID {
				continue
			}
			if _, mine := g.owned[o.ID]; mine {
				continue
			}

			g.w.assets[o.ID] = o
			steps, err := g.w.steps(o)
			if err != nil {
				return err
			}
			for _, s := range steps {
				if !s.forward || s.edge.Label != "common_name" {
					continue
				}

				witness := append(g.pathTo(cert.ID), matched(cert, o, "same_"+def.Params.Attribute, value),
					witnessOf(s.edge, o, s.other))
				g.add(s.other, def.ID, "TLSCertificate "+def.Params.Attribute+" TLSCertificate", witness)
			}
		}
	}

	return nil
}

// maxChainDepth bounds the issuing certificates walked above a certificate.
const maxChainDepth = 4

// privateChain reports whether cert was issued by a private CA: its issuing
// certificate is stored, and no name on the chain above it (the issuer and
// subject names of each issuing certificate) names a public certificate
// authority. Public intermediates go by short codes (R11, WE1) that a list
// cannot keep up with, but they chain to well-known roots (ISRG Root X1, GTS
// Root R4), so the walk finds them. An unknown chain is not private.
func (g *gapSearch) privateChain(cert Asset, public []string) (bool, error) {
	cur := cert
	issued := false
	for depth := 0; depth < maxChainDepth; depth++ {
		if publicIssuer(contentString(cur, "issuer_common_name"), public) ||
			(cur.ID != cert.ID && publicIssuer(contentString(cur, "subject_common_name"), public)) {
			return false, nil
		}

		steps, err := g.w.steps(cur)
		if err != nil {
			return false, err
		}

		var next *Asset
		for _, s := range steps {
			if s.forward && s.edge.Label == "issuing_certificate" && s.other.Type == "TLSCertificate" &&
				s.other.ID != cur.ID {
				next = &s.other
				break
			}
		}
		if next == nil {
			break
		}

		issued, cur = true, *next
	}

	return issued, nil
}

// publicIssuer reports whether an issuer common name names a public
// certificate authority. Entries of three characters or fewer (Let's
// Encrypt's R3, E5) must match the whole name; longer ones match anywhere.
func publicIssuer(issuer string, public []string) bool {
	issuer = strings.ToLower(strings.TrimSpace(issuer))
	if issuer == "" || len(public) == 0 {
		return false
	}
	for _, p := range public {
		p = strings.ToLower(p)
		if len(strings.TrimSpace(p)) <= 3 {
			if issuer == strings.TrimSpace(p) {
				return true
			}
		} else if strings.Contains(issuer, p) {
			return true
		}
	}

	return false
}

// hostWithin reports whether host is domain or a name below it.
func hostWithin(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	domain = strings.ToLower(domain)
	return host != "" && (host == domain || strings.HasSuffix(host, "."+domain))
}
