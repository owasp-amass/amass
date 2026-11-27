// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensCertificates asks for the certificate posture of a domain or
// organization.
const LensCertificates = "certificates"

var certificatesLens = SubjectLens{
	Name:    LensCertificates,
	Command: "certificates",
	Description: "Show the certificates of what a domain or organization controls: which expire soon or have " +
		"expired, weak or overlong ones, wildcards and the hosts they cover, and the authorities relied on. Read-only",
	Examples: []string{"Which of <domain>'s certificates expire this month?",
		"Which certificate authorities does <organization> use?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindCertificates(ctx, g, schema, root, opts.Limits)
	},
}

// Certificate finding kinds, most severe first.
const (
	CertExpired    = "expired"
	CertExpiring   = "expiring"
	CertWeak       = "weak_signature"
	CertSelfIssued = "self_issued"
	CertOverlong   = "overlong_validity"
	CertWildcard   = "wildcard"
	CertShared     = "covers_other_domains"
	CertNoCAA      = "no_caa"
)

var certOrder = []string{CertExpired, CertExpiring, CertWeak, CertSelfIssued, CertOverlong, CertWildcard, CertShared, CertNoCAA}

// CertificateFinding is one certificate that stands out.
type CertificateFinding struct {
	Kind     string   `json:"kind"`
	Subject  string   `json:"subject"`
	ID       string   `json:"id"`
	Issuer   string   `json:"issuer"`
	NotAfter string   `json:"not_after,omitempty"`
	Names    int      `json:"names"`
	Services int      `json:"services"`
	Examples []string `json:"examples,omitempty"`
	Detail   string   `json:"detail"`
}

// CertificatesReport is the result of the certificates lens.
type CertificatesReport struct {
	lensBase
	Certificates int `json:"certificates"`
	// Issuers are the authorities that issued the certificates, by count.
	Issuers []ChangeGroup `json:"issuers"`
	// AuthorizedCAs lists, per owned apex domain that publishes a CAA
	// policy, the certificate authorities that policy permits to issue.
	AuthorizedCAs []DomainCAs `json:"authorized_cas,omitempty"`
	// MarkCertificates are the BIMI mark certificates among them, with the
	// organization and mark the certificate authority verified.
	MarkCertificates []MarkCertificate    `json:"mark_certificates,omitempty"`
	Findings         []CertificateFinding `json:"findings"`
}

// MarkCertificate is a mark certificate (a Verified or Common Mark
// Certificate) a domain publishes for Brand Indicators for Message
// Identification.
type MarkCertificate struct {
	Subject         string   `json:"subject"`
	ID              string   `json:"id"`
	Issuer          string   `json:"issuer"`
	NotAfter        string   `json:"not_after,omitempty"`
	Domains         []string `json:"domains,omitempty"`
	Organization    string   `json:"organization,omitempty"`
	MarkType        string   `json:"mark_type,omitempty"`
	WordMark        string   `json:"word_mark,omitempty"`
	Trademark       string   `json:"trademark,omitempty"`
	TrademarkOffice string   `json:"trademark_office,omitempty"`
	LEI             string   `json:"lei,omitempty"`
	Logo            string   `json:"logo,omitempty"`
}

// DomainCAs is the set of certificate authorities a domain's CAA policy
// authorizes to issue certificates for it.
type DomainCAs struct {
	Domain string   `json:"domain"`
	CAs    []string `json:"cas"`
}

var certificatesJSON = semantics.File("certificates.json")

type certificateRules struct {
	License            string            `json:"_license"`
	About              string            `json:"_about"`
	CertificatePurpose string            `json:"certificate_purpose"`
	CertificateTypes   []string          `json:"certificate_types"`
	NameTypes          []string          `json:"name_types"`
	ServiceTypes       []string          `json:"service_types"`
	Fields             map[string]string `json:"fields"`
	ExpiryWarningDays  int               `json:"expiry_warning_days"`
	WeakSignatures     []string          `json:"weak_signature_algorithms"`
	MaxValidity        []struct {
		IssuedFrom string `json:"issued_from"`
		Days       int    `json:"days"`
		from       time.Time
	} `json:"max_validity"`
	MaxValiditySource string `json:"max_validity_source"`
	Authorities       []struct {
		Name    string   `json:"name"`
		Match   []string `json:"match"`
		Issuers []string `json:"issuers"`
	} `json:"authorities"`
	ProviderManagedNames []string `json:"provider_managed_names"`
	MarkCertificates     struct {
		Usage             string `json:"usage"`
		SubjectLabel      string `json:"subject_label"`
		OrganizationLabel string `json:"organization_label"`
		IdentifierLabel   string `json:"identifier_label"`
		TrademarkIDType   string `json:"trademark_id_type"`
		LEIIDType         string `json:"lei_id_type"`
		LogoLabel         string `json:"logo_label"`
		AuthorityLabel    string `json:"authority_label"`
		MarkTypeProperty  string `json:"mark_type_property"`
		WordMarkProperty  string `json:"word_mark_property"`
	} `json:"mark_certificates"`
}

var loadCertificateRules = sync.OnceValue(func() certificateRules {
	var r certificateRules
	if err := graph.DecodeStrict(certificatesJSON, &r); err != nil {
		panic("certificates.json: " + err.Error())
	}
	for _, f := range []string{"subject", "issuer", "not_before", "not_after", "signature_algorithm", "ca"} {
		if r.Fields[f] == "" {
			panic("certificates.json: fields." + f + " is required")
		}
	}
	for i := range r.MaxValidity {
		t, err := time.Parse("2006-01-02", r.MaxValidity[i].IssuedFrom)
		if err != nil || r.MaxValidity[i].Days < 1 {
			panic("certificates.json: max_validity needs issued_from dates and positive days")
		}
		r.MaxValidity[i].from = t
	}
	if r.CertificatePurpose == "" || len(r.CertificateTypes) == 0 {
		panic("certificates.json: certificate_purpose and certificate_types are required")
	}
	if m := r.MarkCertificates; m.Usage == "" || m.SubjectLabel == "" || m.IdentifierLabel == "" ||
		m.TrademarkIDType == "" || m.LEIIDType == "" {
		panic("certificates.json: mark_certificates needs usage, subject_label, identifier_label, " +
			"trademark_id_type and lei_id_type")
	}

	return r
})

// certificateNow is the clock expiry is measured against; tests replace it.
var certificateNow = time.Now

// FindCertificates walks the controlled footprint of a domain or
// organization and reports its certificates: those presented by its
// services or covering its names. It reads only.
func FindCertificates(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (CertificatesReport, error) {
	var out CertificatesReport
	s, err := newScope(ctx, g, schema, root, limits, "certificates")
	if err != nil {
		return out, err
	}

	rules := loadCertificateRules()
	certs := map[string]graph.Asset{}
	var order []string
	add := func(a graph.Asset) {
		if _, ok := certs[a.ID]; !ok && slices.Contains(rules.CertificateTypes, a.Type) &&
			!contentBool(a, rules.Fields["ca"]) {
			certs[a.ID] = a
			order = append(order, a.ID)
		}
	}
	for _, id := range s.order {
		if s.spent() {
			break
		}
		a := s.owned[id]
		if slices.Contains(rules.CertificateTypes, a.Type) {
			add(a)
			continue
		}
		steps, err := s.w.steps(a)
		if err != nil {
			return out, err
		}
		for _, st := range steps {
			if st.purpose == rules.CertificatePurpose {
				add(st.other)
			}
		}
	}

	issuers := changeTally{examples: 3, groups: map[string]map[string]*ChangeGroup{}}
	var findings []CertificateFinding
	var marks []MarkCertificate
	for _, id := range order {
		if s.spent() {
			break
		}
		f, issuer, err := s.certificate(certs[id], rules)
		if err != nil {
			return out, err
		}
		issuers.add("issuers", issuer, graph.ContentString(certs[id], rules.Fields["subject"]))

		if isMarkCertificate(certs[id], rules) {
			m, err := s.markCertificate(certs[id], rules, issuer)
			if err != nil {
				return out, err
			}
			marks = append(marks, m)
			// The Baseline Requirements' validity limits are for TLS server
			// certificates; mark certificates follow their own rules.
			f = slices.DeleteFunc(f, func(c CertificateFinding) bool { return c.Kind == CertOverlong })
		}
		findings = append(findings, f...)
	}
	sort.SliceStable(marks, func(i, j int) bool { return marks[i].Subject < marks[j].Subject })
	out.MarkCertificates = marks

	authorized, noCAA := s.certificateAuthority()
	out.AuthorizedCAs = authorized
	findings = append(findings, noCAA...)

	rank := map[string]int{}
	for i, k := range certOrder {
		rank[k] = i
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if rank[a.Kind] != rank[b.Kind] {
			return rank[a.Kind] < rank[b.Kind]
		}
		if a.NotAfter != b.NotAfter {
			return a.NotAfter < b.NotAfter
		}
		return a.Subject < b.Subject
	})

	out.lensBase = s.base()
	out.Certificates = len(order)
	out.Issuers = issuers.list("issuers")
	out.Findings = findings
	return out, nil
}

// Text implements Report.
func (r CertificatesReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Certificates of %s: %d from %d controlled asset(s) (%d reads).\n", subject, r.Certificates,
		r.Footprint, r.Reads)
	if len(r.Issuers) > 0 {
		b.WriteString("\nIssued by:\n")
		for _, i := range r.Issuers {
			fmt.Fprintf(&b, "  %s: %d, e.g. %s\n", i.Key, i.Count, strings.Join(i.Examples, ", "))
		}
	}
	if len(r.AuthorizedCAs) > 0 {
		b.WriteString("\nAuthorized to issue (CAA):\n")
		for _, d := range r.AuthorizedCAs {
			fmt.Fprintf(&b, "  %s: %s\n", d.Domain, strings.Join(d.CAs, ", "))
		}
	}

	if len(r.MarkCertificates) > 0 {
		b.WriteString("\nMark certificates (BIMI):\n")
		for _, m := range r.MarkCertificates {
			fmt.Fprintf(&b, "  %s (%s)", m.Subject, m.Issuer)
			var parts []string
			if m.Organization != "" {
				parts = append(parts, "verified organization "+m.Organization)
			}
			if m.Trademark != "" {
				tm := "trademark " + m.Trademark
				if m.TrademarkOffice != "" {
					tm += " (" + m.TrademarkOffice + ")"
				}
				parts = append(parts, tm)
			}
			if m.WordMark != "" {
				parts = append(parts, "word mark "+m.WordMark)
			}
			if m.MarkType != "" {
				parts = append(parts, strings.ToLower(m.MarkType))
			}
			if m.LEI != "" {
				parts = append(parts, "LEI "+m.LEI)
			}
			if len(m.Domains) > 0 {
				parts = append(parts, "for "+strings.Join(m.Domains[:min(5, len(m.Domains))], ", "))
			}
			if m.NotAfter != "" {
				parts = append(parts, "until "+m.NotAfter)
			}
			if len(parts) > 0 {
				b.WriteString(": " + strings.Join(parts, "; "))
			}
			b.WriteString("\n")
		}
	}

	titles := map[string]string{CertExpired: "Expired", CertExpiring: "Expiring soon",
		CertWeak: "Weak signature algorithm", CertSelfIssued: "Self-issued", CertOverlong: "Longer than allowed",
		CertWildcard: "Wildcards", CertShared: "Covering other domains", CertNoCAA: "No CAA policy"}
	for _, kind := range certOrder {
		var lines []string
		for _, f := range r.Findings {
			if f.Kind == kind {
				var line string
				if kind == CertNoCAA {
					line = "  " + f.Detail
				} else {
					line = fmt.Sprintf("  %s (%s): %s", f.Subject, f.Issuer, f.Detail)
				}
				if len(f.Examples) > 0 && kind != CertShared {
					line += "; e.g. " + strings.Join(f.Examples, ", ")
				}
				lines = append(lines, line)
			}
		}
		if len(lines) > 0 {
			fmt.Fprintf(&b, "\n%s (%d):\n%s\n", titles[kind], len(lines), strings.Join(lines, "\n"))
		}
	}
	if r.Certificates == 0 {
		b.WriteString("No certificate is stored for what it controls.\n")
	}

	b.WriteString("\nThese are certificates stored by past enumerations, not a live scan." + r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r CertificatesReport) Facts() []string {
	var out []string
	for _, i := range r.Issuers {
		out = append(out, "issuer "+i.Key)
	}
	for _, m := range r.MarkCertificates {
		out = append(out, "mark_certificate "+m.Subject)
		if m.Trademark != "" {
			out = append(out, "trademark "+m.Trademark)
		}
	}
	for _, f := range r.Findings {
		out = append(out, f.Kind+" "+f.Subject)
	}
	return out
}
