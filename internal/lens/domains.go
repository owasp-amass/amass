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

// LensDomains asks for the domain portfolio of a domain or organization.
const LensDomains = "domains"

var domainsLens = SubjectLens{
	Name:    LensDomains,
	Command: "domains",
	Description: "List the registered domains of a domain or organization: registrar, expiry, transfer lock, " +
		"DNSSEC and DNS providers, with those expiring soon or unlocked first. Read-only",
	Examples: []string{"Which of <organization>'s domains expire soon?", "Which registrars does <domain> use?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindDomains(ctx, g, schema, root, opts.Limits)
	},
}

// Domain finding kinds, most severe first.
const (
	DomainExpired    = "expired"
	DomainExpiring   = "expiring"
	DomainUnlocked   = "no_transfer_lock"
	DomainNoRecord   = "no_registration"
	DomainNoDNSSEC   = "unsigned"
	domainsExamples  = 3
	domainUnknownTag = "unknown"
)

var domainOrder = []string{DomainExpired, DomainExpiring, DomainUnlocked, DomainNoRecord, DomainNoDNSSEC}

// DomainEntry is one registered domain of the subject.
type DomainEntry struct {
	Domain      string   `json:"domain"`
	Names       int      `json:"names"`
	Registered  bool     `json:"registered"`
	Registrar   string   `json:"registrar,omitempty"`
	Created     string   `json:"created,omitempty"`
	Expires     string   `json:"expires,omitempty"`
	Status      []string `json:"status,omitempty"`
	DNSSEC      bool     `json:"dnssec"`
	NameServers []string `json:"name_servers,omitempty"`
}

// DomainFinding is one domain that stands out.
type DomainFinding struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
	Detail string `json:"detail"`
}

// DomainsReport is the result of the domains lens.
type DomainsReport struct {
	lensBase
	Domains    []DomainEntry   `json:"domains"`
	Registrars []ChangeGroup   `json:"registrars"`
	DNS        []ChangeGroup   `json:"dns_providers"`
	Findings   []DomainFinding `json:"findings"`
}

var domainsJSON = semantics.File("domains.json")

type domainRules struct {
	License             string            `json:"_license"`
	About               string            `json:"_about"`
	RegistrationPurpose string            `json:"registration_purpose"`
	RecordTypes         []string          `json:"record_types"`
	RegistrarLabels     []string          `json:"registrar_labels"`
	NameServerLabels    []string          `json:"name_server_labels"`
	Fields              map[string]string `json:"fields"`
	ExpiryWarningDays   int               `json:"expiry_warning_days"`
	TransferLocks       []string          `json:"transfer_lock_statuses"`
	StatusSource        string            `json:"status_source"`
}

var loadDomainRules = sync.OnceValue(func() domainRules {
	var r domainRules
	if err := graph.DecodeStrict(domainsJSON, &r); err != nil {
		panic("domains.json: " + err.Error())
	}
	for _, f := range []string{"domain", "created", "expires", "status", "dnssec"} {
		if r.Fields[f] == "" {
			panic("domains.json: fields." + f + " is required")
		}
	}
	if r.RegistrationPurpose == "" || len(r.RecordTypes) == 0 {
		panic("domains.json: registration_purpose and record_types are required")
	}

	return r
})

// domainsNow is the clock expiry is measured against; tests replace it.
var domainsNow = time.Now

// statusKey compares registration status codes the way EPP and RDAP spell
// them: clientTransferProhibited and "client transfer prohibited" agree.
func statusKey(s string) string {
	return strings.NewReplacer(" ", "", "_", "", "-", "").Replace(strings.ToLower(s))
}

// FindDomains walks the controlled footprint of a domain or organization and
// reports its registered domains and their registrations. It reads only.
func FindDomains(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (DomainsReport, error) {
	var out DomainsReport
	s, err := newScope(ctx, g, schema, root, limits, "domains")
	if err != nil {
		return out, err
	}

	rules := loadDomainRules()
	entries := map[string]*DomainEntry{}
	records := map[string]graph.Asset{}
	names := map[string]graph.Asset{}
	for _, id := range s.order {
		a := s.owned[id]
		switch {
		case a.Type == "FQDN":
			d := graph.RegisteredDomain(graph.FQDNName(a))
			if d == "" || reservedName(d) {
				continue
			}
			if entries[d] == nil {
				entries[d] = &DomainEntry{Domain: d}
			}
			entries[d].Names++
			if graph.FQDNName(a) == d {
				names[d] = a
			}
		case slices.Contains(rules.RecordTypes, a.Type):
			if d := strings.ToLower(graph.ContentString(a, rules.Fields["domain"])); d != "" {
				records[d] = a
				if entries[d] == nil {
					entries[d] = &DomainEntry{Domain: d}
				}
			}
		}
	}

	registrars := changeTally{examples: domainsExamples, groups: map[string]map[string]*ChangeGroup{}}
	var findings []DomainFinding
	keys := make([]string, 0, len(entries))
	for d := range entries {
		keys = append(keys, d)
	}
	sort.Strings(keys)
	for _, d := range keys {
		if s.spent() {
			break
		}
		e := entries[d]
		rec, ok := records[d]
		if !ok {
			if rec, ok, err = s.registrationOf(names[d], d, rules); err != nil {
				return out, err
			}
		}
		if ok {
			if err := s.readDomainRecord(e, rec, rules); err != nil {
				return out, err
			}
		}
		if e.Registrar != "" {
			registrars.add("registrars", e.Registrar, d)
		}
		for _, ns := range e.NameServers {
			registrars.add("dns", ns, d)
		}
		findings = append(findings, domainFindings(*e, rules)...)
		out.Domains = append(out.Domains, *e)
	}

	rank := map[string]int{}
	for i, k := range domainOrder {
		rank[k] = i
	}
	sort.SliceStable(findings, func(i, j int) bool { return rank[findings[i].Kind] < rank[findings[j].Kind] })
	out.lensBase = s.base()
	out.Registrars, out.DNS = registrars.list("registrars"), registrars.list("dns")
	out.Findings = findings
	return out, nil
}

// registrationOf finds the registration record of a registered domain,
// through its name when the footprint holds it and else by looking the name
// up.
func (s *scope) registrationOf(name graph.Asset, domain string, rules domainRules) (graph.Asset, bool, error) {
	if name.ID == "" {
		resolver, ok := s.w.graph.(graph.AssetResolver)
		if !ok {
			return graph.Asset{}, false, nil
		}
		res, err := resolver.ResolveAsset(s.w.ctx, graph.AssetSelector{Type: "FQDN", Field: "name", Value: domain}, 2)
		if err != nil || len(res.Candidates) == 0 {
			return graph.Asset{}, false, nil
		}
		name = res.Candidates[0].Asset
	}

	steps, err := s.w.steps(name)
	if err != nil {
		return graph.Asset{}, false, err
	}
	for _, st := range steps {
		if st.forward && st.purpose == rules.RegistrationPurpose && slices.Contains(rules.RecordTypes, st.other.Type) {
			return st.other, true, nil
		}
	}

	return graph.Asset{}, false, nil
}

// readDomainRecord fills e from a registration record and the registrar and
// name servers it names.
func (s *scope) readDomainRecord(e *DomainEntry, rec graph.Asset, rules domainRules) error {
	e.Registered = true
	e.Created = graph.ContentString(rec, rules.Fields["created"])
	e.Expires = graph.ContentString(rec, rules.Fields["expires"])
	e.DNSSEC = contentBool(rec, rules.Fields["dnssec"])
	e.Status = contentStrings(rec, rules.Fields["status"])

	steps, err := s.w.steps(rec)
	if err != nil {
		return err
	}
	for _, st := range steps {
		if !st.forward {
			continue
		}
		switch {
		case slices.Contains(rules.RegistrarLabels, st.edge.Label) && e.Registrar == "":
			if p, _, _, err := s.party(st.other); err != nil {
				return err
			} else if p != "" {
				e.Registrar = p
			}
		case slices.Contains(rules.NameServerLabels, st.edge.Label):
			ns := graph.RegisteredDomain(graph.FQDNName(st.other))
			if ns == "" {
				continue
			}
			provider := vendorNameOf(ns)
			if s.ownDomains[ns] {
				provider = "own name servers"
			}
			graph.AddUnique(&e.NameServers, provider)
		}
	}
	sort.Strings(e.NameServers)
	return nil
}

// contentStrings reads a list content field; a single string reads as a
// list of one.
func contentStrings(a graph.Asset, field string) []string {
	var list []string
	if contentField(a, field, &list) {
		return list
	}
	if v := graph.ContentString(a, field); v != "" {
		return []string{v}
	}
	return nil
}

func domainFindings(e DomainEntry, rules domainRules) []DomainFinding {
	var out []DomainFinding
	if !e.Registered {
		return append(out, DomainFinding{Kind: DomainNoRecord, Domain: e.Domain,
			Detail: "no registration record is stored; its expiry and registrar are unknown"})
	}

	now := domainsNow()
	if exp, ok := parseRecordDate(e.Expires); ok {
		switch {
		case exp.Before(now):
			out = append(out, DomainFinding{Kind: DomainExpired, Domain: e.Domain,
				Detail: "the stored registration expired " + exp.Format("2006-01-02") + "; anyone may register it"})
		case exp.Before(now.AddDate(0, 0, rules.ExpiryWarningDays)):
			out = append(out, DomainFinding{Kind: DomainExpiring, Domain: e.Domain,
				Detail: "registration expires " + exp.Format("2006-01-02")})
		}
	}
	if len(e.Status) > 0 && !slices.ContainsFunc(e.Status, func(st string) bool {
		return slices.ContainsFunc(rules.TransferLocks, func(l string) bool { return statusKey(l) == statusKey(st) })
	}) {
		out = append(out, DomainFinding{Kind: DomainUnlocked, Domain: e.Domain,
			Detail: fmt.Sprintf("no transfer lock among its statuses (%s; %s)", strings.Join(e.Status, ", "),
				rules.StatusSource)})
	}
	if !e.DNSSEC {
		out = append(out, DomainFinding{Kind: DomainNoDNSSEC, Domain: e.Domain, Detail: "not signed with DNSSEC"})
	}

	return out
}

// Text implements Report.
func (r DomainsReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Registered domains of %s: %d from %d controlled asset(s) (%d reads).\n", subject, len(r.Domains),
		r.Footprint, r.Reads)

	titles := map[string]string{DomainExpired: "Expired", DomainExpiring: "Expiring soon",
		DomainUnlocked: "No transfer lock", DomainNoRecord: "No registration stored", DomainNoDNSSEC: "Not signed (DNSSEC)"}
	for _, kind := range domainOrder {
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

	if len(r.Domains) > 0 {
		b.WriteString("\nDomains:\n")
		for _, d := range r.Domains {
			registrar, expires := d.Registrar, d.Expires
			if registrar == "" {
				registrar = domainUnknownTag
			}
			if t, ok := parseRecordDate(expires); ok {
				expires = t.Format("2006-01-02")
			} else if expires == "" {
				expires = domainUnknownTag
			}
			fmt.Fprintf(&b, "  %s: %d name(s), registrar %s, expires %s", d.Domain, d.Names, registrar, expires)
			if len(d.NameServers) > 0 {
				fmt.Fprintf(&b, ", DNS by %s", strings.Join(d.NameServers, ", "))
			}
			b.WriteString("\n")
		}
	}
	for _, g := range []struct {
		title  string
		groups []ChangeGroup
	}{{"Registrars", r.Registrars}, {"DNS providers", r.DNS}} {
		if len(g.groups) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s:\n", g.title)
		for _, x := range g.groups {
			fmt.Fprintf(&b, "  %s: %d domain(s)\n", x.Key, x.Count)
		}
	}

	b.WriteString("\nThese are stored registration records, not a live lookup." + r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r DomainsReport) Facts() []string {
	var out []string
	for _, d := range r.Domains {
		out = append(out, "domain "+d.Domain)
	}
	for _, f := range r.Findings {
		out = append(out, f.Kind+" "+f.Domain)
	}
	return out
}
