// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensEmail asks how well a domain or organization's mail domains are
// protected against spoofing.
const LensEmail = "email"

var emailLens = SubjectLens{
	Name:    LensEmail,
	Command: "email",
	Description: "Show the mail security of a domain or organization's domains: mail providers, SPF and DMARC " +
		"policies and DKIM keys, and which domains can be spoofed. Read-only",
	Examples: []string{"Can <domain> be spoofed in email?", "Who handles <organization>'s mail?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindEmailSecurity(ctx, g, schema, root, opts.Limits)
	},
}

// Email finding kinds, most severe first.
const (
	EmailSPFPermissive = "spf_allows_anyone"
	EmailNoSPF         = "no_spf"
	EmailParked        = "unprotected_non_mail_domain"
	EmailNoDMARC       = "no_dmarc"
	EmailDMARCMonitor  = "dmarc_monitor_only"
	EmailDMARCPartial  = "dmarc_partial"
	EmailSPFSoftfail   = "spf_softfail"
)

var emailOrder = []string{EmailSPFPermissive, EmailNoSPF, EmailParked, EmailNoDMARC, EmailDMARCMonitor,
	EmailDMARCPartial, EmailSPFSoftfail}

// MailDomain is the mail posture of one registered domain.
type MailDomain struct {
	Domain       string   `json:"domain"`
	MailServers  []string `json:"mail_providers,omitempty"`
	SPF          string   `json:"spf,omitempty"`
	DMARC        string   `json:"dmarc,omitempty"`
	DMARCPolicy  string   `json:"dmarc_policy,omitempty"`
	DKIMSelector []string `json:"dkim_selectors,omitempty"`
}

// EmailFinding is one domain that stands out.
type EmailFinding struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
	Detail string `json:"detail"`
	Source string `json:"source,omitempty"`
}

// EmailReport is the result of the email lens.
type EmailReport struct {
	lensBase
	Domains   []MailDomain   `json:"domains"`
	Providers []ChangeGroup  `json:"providers"`
	Findings  []EmailFinding `json:"findings"`
}

var emailJSON = semantics.File("email.json")

type emailRules struct {
	License         string            `json:"_license"`
	About           string            `json:"_about"`
	SPFPrefix       string            `json:"spf_prefix"`
	DMARCPrefix     string            `json:"dmarc_prefix"`
	DKIMPrefix      string            `json:"dkim_prefix"`
	DMARCLabel      string            `json:"dmarc_label"`
	DKIMLabel       string            `json:"dkim_label"`
	PermissiveAll   []string          `json:"permissive_all"`
	SoftfailAll     []string          `json:"softfail_all"`
	MonitorPolicies []string          `json:"monitor_policies"`
	NoneSPF         string            `json:"none_spf"`
	Sources         map[string]string `json:"sources"`
}

var loadEmailRules = sync.OnceValue(func() emailRules {
	var r emailRules
	if err := graph.DecodeStrict(emailJSON, &r); err != nil {
		panic("email.json: " + err.Error())
	}
	if r.SPFPrefix == "" || r.DMARCPrefix == "" || r.DMARCLabel == "" || r.DKIMLabel == "" {
		panic("email.json: spf_prefix, dmarc_prefix, dmarc_label and dkim_label are required")
	}

	return r
})

// FindEmailSecurity walks the controlled footprint of a domain or
// organization and reports, for each of its registered domains, who handles
// its mail and how its SPF, DMARC and DKIM records protect it from being
// spoofed. It reads only.
func FindEmailSecurity(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (EmailReport, error) {
	var out EmailReport
	s, err := newScope(ctx, g, schema, root, limits, "email")
	if err != nil {
		return out, err
	}

	rules := loadEmailRules()
	apexes := map[string]graph.Asset{}
	dkim := map[string][]string{}
	for _, id := range s.order {
		a := s.owned[id]
		if a.Type != "FQDN" {
			continue
		}
		name := graph.FQDNName(a)
		d := graph.RegisteredDomain(name)
		if d == "" || reservedName(d) {
			continue
		}
		if _, ok := apexes[d]; !ok {
			apexes[d] = graph.Asset{}
		}
		if name == d {
			apexes[d] = a
		}
		// selector._domainkey.domain
		if sel, ok := strings.CutSuffix(name, "."+rules.DKIMLabel+"."+d); ok {
			txt, err := graph.TXTValues(ctx, g, a.ID)
			if err != nil {
				return out, err
			}
			if slices.ContainsFunc(txt, func(t string) bool { return hasPrefixFold(t, rules.DKIMPrefix) }) {
				list := dkim[d]
				graph.AddUnique(&list, sel)
				dkim[d] = list
			}
		}
	}

	providers := changeTally{examples: 3, groups: map[string]map[string]*ChangeGroup{}}
	keys := make([]string, 0, len(apexes))
	for d := range apexes {
		keys = append(keys, d)
	}
	sort.Strings(keys)
	for _, d := range keys {
		if s.spent() {
			break
		}
		m, err := s.mailDomain(d, apexes[d], rules)
		if err != nil {
			return out, err
		}
		m.DKIMSelector = dkim[d]
		for _, p := range m.MailServers {
			providers.add("providers", p, d)
		}
		out.Findings = append(out.Findings, emailFindings(m, rules)...)
		out.Domains = append(out.Domains, m)
	}

	rank := map[string]int{}
	for i, k := range emailOrder {
		rank[k] = i
	}
	sort.SliceStable(out.Findings, func(i, j int) bool { return rank[out.Findings[i].Kind] < rank[out.Findings[j].Kind] })
	out.lensBase = s.base()
	out.Providers = providers.list("providers")
	return out, nil
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// lookupName finds a stored name, in the footprint or by looking it up.
func (s *scope) lookupName(name string) (graph.Asset, bool) {
	for _, id := range s.order {
		if a := s.owned[id]; a.Type == "FQDN" && graph.FQDNName(a) == name {
			return a, true
		}
	}
	resolver, ok := s.w.graph.(graph.AssetResolver)
	if !ok {
		return graph.Asset{}, false
	}
	res, err := resolver.ResolveAsset(s.w.ctx, graph.AssetSelector{Type: "FQDN", Field: "name", Value: name}, 2)
	if err != nil || len(res.Candidates) == 0 {
		return graph.Asset{}, false
	}
	return res.Candidates[0].Asset, true
}

// mailDomain reads one domain's mail servers and policies.
func (s *scope) mailDomain(domain string, apex graph.Asset, rules emailRules) (MailDomain, error) {
	m := MailDomain{Domain: domain}
	if apex.ID == "" {
		var ok bool
		if apex, ok = s.lookupName(domain); !ok {
			return m, nil
		}
	}

	steps, err := s.w.steps(apex)
	if err != nil {
		return m, err
	}
	for _, st := range steps {
		if !st.forward || !mailRR(st.edge) {
			continue
		}
		host := graph.RegisteredDomain(graph.FQDNName(st.other))
		provider := vendorNameOf(host)
		if s.ownDomains[host] {
			provider = "own mail servers"
		}
		graph.AddUnique(&m.MailServers, provider)
	}
	sort.Strings(m.MailServers)

	txt, err := graph.TXTValues(s.w.ctx, s.w.graph, apex.ID)
	if err != nil {
		return m, err
	}
	for _, t := range txt {
		if hasPrefixFold(t, rules.SPFPrefix) {
			m.SPF = t
		}
	}

	if dm, ok := s.lookupName(rules.DMARCLabel + "." + domain); ok {
		txt, err := graph.TXTValues(s.w.ctx, s.w.graph, dm.ID)
		if err != nil {
			return m, err
		}
		for _, t := range txt {
			if hasPrefixFold(t, rules.DMARCPrefix) {
				m.DMARC = t
				m.DMARCPolicy = dmarcTag(t, "p")
			}
		}
	}

	return m, nil
}

// dmarcTag returns one tag's value of a DMARC record (RFC 7489 section 6.4).
func dmarcTag(record, tag string) string {
	for _, part := range strings.Split(record, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), tag) {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
}

// spfAll returns the all mechanism of an SPF record with its qualifier, or
// "" when it has none (it may end in a redirect instead).
func spfAll(record string) string {
	for _, term := range strings.Fields(strings.ToLower(record)) {
		if strings.TrimLeft(term, "+-~?") == "all" {
			return term
		}
	}
	return ""
}

func emailFindings(m MailDomain, rules emailRules) []EmailFinding {
	var out []EmailFinding
	add := func(kind, detail, source string) {
		out = append(out, EmailFinding{Kind: kind, Domain: m.Domain, Detail: detail, Source: rules.Sources[source]})
	}

	all := spfAll(m.SPF)
	switch {
	case m.SPF == "":
		add(EmailNoSPF, "no SPF record is stored, so receivers cannot tell forged mail from it", "spf")
	case slices.Contains(rules.PermissiveAll, all):
		add(EmailSPFPermissive, fmt.Sprintf("its SPF record ends in %s, so any server may send as it", all), "spf")
	case slices.Contains(rules.SoftfailAll, all):
		add(EmailSPFSoftfail, "its SPF record ends in "+all+", which marks forged mail but does not reject it", "spf")
	}

	switch {
	case m.DMARC == "":
		add(EmailNoDMARC, "no DMARC record is stored (check that its "+rules.DMARCLabel+" name was enumerated)", "dmarc")
	case slices.Contains(rules.MonitorPolicies, m.DMARCPolicy):
		add(EmailDMARCMonitor, "its DMARC policy is p="+m.DMARCPolicy+", so spoofed mail is still delivered", "dmarc")
	default:
		if pct, err := strconv.Atoi(dmarcTag(m.DMARC, "pct")); err == nil && pct < 100 {
			add(EmailDMARCPartial, fmt.Sprintf("its DMARC policy applies to %d%% of failing mail", pct), "dmarc")
		}
	}

	if len(m.MailServers) == 0 && (!strings.EqualFold(strings.TrimSpace(m.SPF), rules.NoneSPF) ||
		m.DMARCPolicy != "reject") {
		add(EmailParked, fmt.Sprintf("has no mail server stored but does not publish %q and a DMARC reject policy; "+
			"a domain that sends no mail can still be spoofed", rules.NoneSPF), "dmarc")
	}

	return out
}

// Text implements Report.
func (r EmailReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Mail security of %s: %d domain(s) from %d controlled asset(s) (%d reads).\n", subject,
		len(r.Domains), r.Footprint, r.Reads)

	titles := map[string]string{EmailSPFPermissive: "SPF lets anyone send", EmailNoSPF: "No SPF record",
		EmailParked: "Domains without mail that can still be spoofed", EmailNoDMARC: "No DMARC record",
		EmailDMARCMonitor: "DMARC monitoring only", EmailDMARCPartial: "DMARC applied to part of the mail",
		EmailSPFSoftfail: "SPF softfail"}
	for _, kind := range emailOrder {
		var lines []string
		for _, f := range r.Findings {
			if f.Kind == kind {
				lines = append(lines, fmt.Sprintf("  %s: %s", f.Domain, f.Detail))
			}
		}
		if len(lines) > 0 {
			fmt.Fprintf(&b, "\n%s (%d):\n%s\n", titles[kind], len(lines), strings.Join(lines, "\n"))
		}
	}
	if len(r.Providers) > 0 {
		b.WriteString("\nMail handled by:\n")
		for _, p := range r.Providers {
			fmt.Fprintf(&b, "  %s: %d domain(s), e.g. %s\n", p.Key, p.Count, strings.Join(p.Examples, ", "))
		}
	}

	b.WriteString("\nThese are stored DNS records, not a live lookup; SPF RFC 7208, DMARC RFC 7489." +
		r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r EmailReport) Facts() []string {
	var out []string
	for _, p := range r.Providers {
		out = append(out, "mail by "+p.Key)
	}
	for _, f := range r.Findings {
		out = append(out, f.Kind+" "+f.Domain)
	}
	return out
}
