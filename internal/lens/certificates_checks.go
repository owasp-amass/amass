// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// certificateAuthority reads the CAA policy of each owned apex domain and
// reports which certificate authorities it authorizes. A domain that
// publishes no issuance policy (no CAA, or only iodef) lets any CA issue for
// it, which is reported as a no_caa finding.
func (s *scope) certificateAuthority() ([]DomainCAs, []CertificateFinding) {
	var authorized []DomainCAs
	var without []string
	seen := map[string]bool{}
	for _, id := range s.order {
		if s.spent() {
			break
		}
		a := s.owned[id]
		if a.Type != "FQDN" {
			continue
		}
		name := graph.FQDNName(a)
		if name == "" || name != graph.RegisteredDomain(name) || reservedName(name) || seen[name] {
			continue
		}
		seen[name] = true

		values, err := graph.CAAValues(s.w.ctx, s.w.graph, id)
		if err != nil {
			continue
		}
		if cas := caaAuthorizedCAs(values); len(cas) > 0 {
			authorized = append(authorized, DomainCAs{Domain: name, CAs: cas})
		} else {
			without = append(without, name)
		}
	}

	sort.Slice(authorized, func(i, j int) bool { return authorized[i].Domain < authorized[j].Domain })
	sort.Strings(without)

	var findings []CertificateFinding
	if len(without) > 0 {
		examples := without
		if len(examples) > 5 {
			examples = examples[:5]
		}
		findings = append(findings, CertificateFinding{
			Kind:     CertNoCAA,
			Subject:  without[0],
			Names:    len(without),
			Examples: examples,
			Detail: fmt.Sprintf("%d owned domain(s) publish no CAA policy, so any certificate authority "+
				"may issue certificates for them", len(without)),
		})
	}
	return authorized, findings
}

// caaAuthorizedCAs extracts the certificate authorities permitted by a set of
// CAA records. Each record reads `<flags> <tag> "<value>"`; only issue and
// issuewild tags restrict issuance, and the authority is the hostname before
// any parameters. An empty value (`;`) forbids issuance and authorizes no CA.
func caaAuthorizedCAs(values []string) []string {
	seen := map[string]bool{}
	var cas []string
	for _, v := range values {
		tag, value, ok := parseCAA(v)
		if !ok || (tag != "issue" && tag != "issuewild") {
			continue
		}
		ca := strings.TrimSpace(value)
		if i := strings.IndexByte(ca, ';'); i >= 0 {
			ca = strings.TrimSpace(ca[:i])
		}
		if ca == "" || seen[ca] {
			continue
		}
		seen[ca] = true
		cas = append(cas, ca)
	}
	sort.Strings(cas)
	return cas
}

// parseCAA splits a CAA rdata string `<flags> <tag> "<value>"` into its tag
// and unquoted value.
func parseCAA(s string) (tag, value string, ok bool) {
	fields := strings.SplitN(strings.TrimSpace(s), " ", 3)
	if len(fields) != 3 {
		return "", "", false
	}
	return strings.ToLower(fields[1]), strings.Trim(fields[2], `"`), true
}

// CertificateAuthority returns the public certificate authority an issuer
// name is (its organization, or the common name of the issuing certificate,
// such as Let's Encrypt's R10), from the certificates catalog's authorities,
// and whether it is one.
func CertificateAuthority(issuer string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(issuer))
	if name == "" {
		return "", false
	}
	for _, a := range loadCertificateRules().Authorities {
		if slices.Contains(a.Issuers, name) ||
			slices.ContainsFunc(a.Match, func(m string) bool { return strings.Contains(name, m) }) {
			return a.Name, true
		}
	}
	return "", false
}

// isMarkCertificate reports whether a certificate is a BIMI mark certificate:
// its extended key usage names mark_certificates.usage.
func isMarkCertificate(cert graph.Asset, rules certificateRules) bool {
	return slices.Contains(contentStrings(cert, rules.Fields["ext_key_usage"]), rules.MarkCertificates.Usage)
}

// ProviderManagedName reports whether a name a certificate covers marks it
// as one a CDN or hosting provider manages for many customers: the name is a
// provider_managed_names entry or below one.
func ProviderManagedName(name string) bool {
	name = strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(name), "."), "*."))
	for _, p := range loadCertificateRules().ProviderManagedNames {
		if HostWithin(name, p) {
			return true
		}
	}
	return false
}

// PublicIssuer reports whether an issuer name names a public certificate
// authority (CertificateAuthority).
func PublicIssuer(issuer string) bool {
	_, ok := CertificateAuthority(issuer)
	return ok
}

// certificate reads one certificate's names, services and issuer and
// returns what stands out about it.
func (s *scope) certificate(cert graph.Asset, rules certificateRules) ([]CertificateFinding, string, error) {
	steps, err := s.w.steps(cert)
	if err != nil {
		return nil, "", err
	}

	subject := graph.ContentString(cert, rules.Fields["subject"])
	issuer := graph.ContentString(cert, rules.Fields["issuer"])
	var names, outside []string
	services := 0
	issuerParty := ""
	for _, st := range steps {
		switch {
		case st.forward && slices.Contains(rules.NameTypes, st.other.Type):
			n := graph.FQDNName(st.other)
			graph.AddUnique(&names, n)
			if d := graph.RegisteredDomain(strings.TrimPrefix(n, "*.")); d != "" && !s.ownDomains[d] {
				graph.AddUnique(&outside, d)
			}
		case !st.forward && slices.Contains(rules.ServiceTypes, st.other.Type):
			services++
		case st.forward && st.attr == graph.AttrThirdParty && st.purpose == rules.CertificatePurpose &&
			issuerParty == "" && st.vendor:
			if p, _, _, err := s.party(st.other); err == nil && p != "" {
				issuerParty = p
			}
		}
	}
	sort.Strings(names)
	// a certificate may name its subject only in its alternative names
	if subject == "" && len(names) > 0 {
		subject = names[0]
	}
	if issuerParty == "" {
		issuerParty = issuer
	}
	if ca, ok := CertificateAuthority(issuerParty); ok {
		issuerParty = ca
	}
	if issuerParty == "" {
		issuerParty = "unknown issuer"
	}

	base := CertificateFinding{Subject: subject, ID: cert.ID, Issuer: issuerParty,
		NotAfter: graph.ContentString(cert, rules.Fields["not_after"]), Names: len(names), Services: services}
	if len(names) > 0 {
		base.Examples = names[:min(3, len(names))]
	}
	var out []CertificateFinding
	finding := func(kind, detail string) {
		f := base
		f.Kind, f.Detail = kind, detail
		out = append(out, f)
	}

	now := certificateNow()
	notBefore, okBefore := parseRecordDate(graph.ContentString(cert, rules.Fields["not_before"]))
	notAfter, okAfter := parseRecordDate(base.NotAfter)
	switch {
	case okAfter && notAfter.Before(now):
		finding(CertExpired, fmt.Sprintf("expired %s", notAfter.Format("2006-01-02")))
	case okAfter && notAfter.Before(now.AddDate(0, 0, rules.ExpiryWarningDays)):
		finding(CertExpiring, fmt.Sprintf("expires %s", notAfter.Format("2006-01-02")))
	}
	if alg := graph.ContentString(cert, rules.Fields["signature_algorithm"]); slices.ContainsFunc(rules.WeakSignatures,
		func(w string) bool { return strings.EqualFold(w, alg) }) {
		finding(CertWeak, "signed with "+alg)
	}
	if subject != "" && strings.EqualFold(subject, issuer) {
		finding(CertSelfIssued, "issued by its own subject, so no browser trusts it")
	}
	if okBefore && okAfter {
		if limit := maxValidityDays(rules, notBefore); limit > 0 &&
			notAfter.Sub(notBefore) > time.Duration(limit+1)*24*time.Hour {
			finding(CertOverlong, fmt.Sprintf("valid %d days from %s; certificates issued then may last %d (%s)",
				int(notAfter.Sub(notBefore).Hours()/24), notBefore.Format("2006-01-02"), limit, rules.MaxValiditySource))
		}
	}
	if strings.HasPrefix(subject, "*.") || slices.ContainsFunc(names, func(n string) bool {
		return strings.HasPrefix(n, "*.")
	}) {
		finding(CertWildcard, fmt.Sprintf("wildcard covering %d name(s), presented by %d service(s); one key "+
			"compromise exposes them all", len(names), services))
	}
	if len(outside) > 0 {
		sort.Strings(outside)
		finding(CertShared, "also covers names of "+strings.Join(outside[:min(5, len(outside))], ", "))
	}

	return out, issuerParty, nil
}

// markCertificate reads what a mark certificate's subject ContactRecord says
// about the organization and its mark.
func (s *scope) markCertificate(cert graph.Asset, rules certificateRules, issuer string) (MarkCertificate, error) {
	mr := rules.MarkCertificates
	m := MarkCertificate{Subject: graph.ContentString(cert, rules.Fields["subject"]), ID: cert.ID, Issuer: issuer,
		NotAfter: graph.ContentString(cert, rules.Fields["not_after"])}
	steps, err := s.w.steps(cert)
	if err != nil {
		return m, err
	}
	for _, st := range steps {
		switch {
		case st.forward && slices.Contains(rules.NameTypes, st.other.Type):
			graph.AddUnique(&m.Domains, graph.FQDNName(st.other))
		case st.forward && st.edge.Label == mr.SubjectLabel:
			if err := s.markSubject(st.other, rules, &m); err != nil {
				return m, err
			}
		}
	}
	sort.Strings(m.Domains)
	if m.Subject == "" && len(m.Domains) > 0 {
		m.Subject = m.Domains[0]
	}
	return m, nil
}

// markSubject fills in the organization and mark details stored on a mark
// certificate's subject ContactRecord.
func (s *scope) markSubject(cr graph.Asset, rules certificateRules, m *MarkCertificate) error {
	mr := rules.MarkCertificates
	if ev, err := s.w.graph.Evidence(s.w.ctx, cr.ID, 50); err == nil {
		if v := propertyValues(ev, mr.MarkTypeProperty); len(v) > 0 {
			m.MarkType = v[0]
		}
		if v := propertyValues(ev, mr.WordMarkProperty); len(v) > 0 {
			m.WordMark = v[0]
		}
	}

	steps, err := s.w.steps(cr)
	if err != nil {
		return err
	}
	for _, st := range steps {
		if !st.forward {
			continue
		}
		switch st.edge.Label {
		case mr.OrganizationLabel:
			if m.Organization == "" {
				m.Organization = graph.AssetLabel(st.other)
			}
		case mr.LogoLabel:
			if m.Logo == "" && st.other.Type == "URL" {
				m.Logo = graph.ContentString(st.other, "url")
			}
		case mr.IdentifierLabel:
			id := graph.ContentString(st.other, "id")
			switch graph.ContentString(st.other, "id_type") {
			case mr.TrademarkIDType:
				m.Trademark = id
				if offices := contactTargets(s.w.ctx, s.w.graph, st.other.ID, mr.AuthorityLabel,
					mr.OrganizationLabel); len(offices) > 0 {
					m.TrademarkOffice = graph.AssetLabel(offices[0])
				}
			case mr.LEIIDType:
				m.LEI = id
			}
		}
	}
	return nil
}

// maxValidityDays is the longest validity allowed for a certificate issued
// at t, or 0 when no rule applies.
func maxValidityDays(rules certificateRules, t time.Time) int {
	days := 0
	for _, m := range rules.MaxValidity {
		if !t.Before(m.from) {
			days = m.Days
		}
	}
	return days
}

// contentField decodes one content field of a, whether the content is a
// map or a stored OAM asset.
func contentField(a graph.Asset, field string, v any) bool {
	data, err := json.Marshal(a.Content)
	if err != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return false
	}
	raw, ok := fields[field]
	return ok && json.Unmarshal(raw, v) == nil
}

// contentBool reads a boolean content field.
func contentBool(a graph.Asset, field string) bool {
	var b bool
	return contentField(a, field, &b) && b
}
