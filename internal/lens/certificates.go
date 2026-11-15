// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"encoding/json"
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
)

var certOrder = []string{CertExpired, CertExpiring, CertWeak, CertSelfIssued, CertOverlong, CertWildcard, CertShared}

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
	Issuers  []ChangeGroup        `json:"issuers"`
	Findings []CertificateFinding `json:"findings"`
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
	for _, id := range order {
		if s.spent() {
			break
		}
		f, issuer, err := s.certificate(certs[id], rules)
		if err != nil {
			return out, err
		}
		issuers.add("issuers", issuer, graph.ContentString(certs[id], rules.Fields["subject"]))
		findings = append(findings, f...)
	}

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

	titles := map[string]string{CertExpired: "Expired", CertExpiring: "Expiring soon",
		CertWeak: "Weak signature algorithm", CertSelfIssued: "Self-issued", CertOverlong: "Longer than allowed",
		CertWildcard: "Wildcards", CertShared: "Covering other domains"}
	for _, kind := range certOrder {
		var lines []string
		for _, f := range r.Findings {
			if f.Kind == kind {
				line := fmt.Sprintf("  %s (%s): %s", f.Subject, f.Issuer, f.Detail)
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
	for _, f := range r.Findings {
		out = append(out, f.Kind+" "+f.Subject)
	}
	return out
}
