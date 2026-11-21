// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensDangling asks for the DNS records of a domain or organization that
// point at something it may no longer hold. The answer is built in Go;
// nothing is written.
const LensDangling = "dangling_dns"

// Dangling DNS finding kinds, most severe first.
const (
	// DanglingClaimable is an alias to a name on a service where anyone can
	// claim it, with no stored address: the classic subdomain takeover.
	DanglingClaimable = "claimable_alias"
	// DanglingExpired is an alias target or name server in a domain whose
	// registration has expired.
	DanglingExpired = "expired_domain"
	// DanglingExpiring is the same with the registration expiring soon.
	DanglingExpiring = "expiring_domain"
	// DanglingUnresolved is an alias to an outside name with no stored
	// address.
	DanglingUnresolved = "unresolved_alias"
	// DanglingLoop is an alias chain that returns to itself or never ends.
	DanglingLoop = "alias_loop"
	// DanglingStale is an address record outside the subject's networks not
	// seen again when its name was last seen.
	DanglingStale = "stale_address"
)

var danglingOrder = []string{DanglingClaimable, DanglingExpired, DanglingExpiring, DanglingUnresolved, DanglingLoop,
	DanglingStale}

// DanglingFinding is one record that may point at something the subject no
// longer holds.
type DanglingFinding struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	NameID string `json:"name_id"`
	// Target is what the record points at: the end of an alias chain, a
	// name server or an address.
	Target string `json:"target"`
	// Via is the alias chain from Name to Target, when there is one.
	Via     []string `json:"via,omitempty"`
	Service string   `json:"service,omitempty"`
	Source  string   `json:"source,omitempty"`
	Detail  string   `json:"detail"`
}

// DanglingReport is the result of the dangling DNS lens.
type DanglingReport struct {
	Root      graph.Asset       `json:"root"`
	Owners    []string          `json:"owners,omitempty"`
	Footprint int               `json:"footprint"`
	Names     int               `json:"names"`
	Findings  []DanglingFinding `json:"findings"`
	Reads     int               `json:"reads"`
	Truncated bool              `json:"truncated"`
	Reason    string            `json:"reason,omitempty"`
}

var danglingJSON = semantics.File("dangling_dns.json")

type claimableService struct {
	Service  string   `json:"service"`
	Patterns []string `json:"patterns"`
	Source   string   `json:"source"`
	res      []*regexp.Regexp
}

type danglingRules struct {
	License             string             `json:"_license"`
	About               string             `json:"_about"`
	RegistrationPurpose string             `json:"registration_purpose"`
	ExpiryFields        []string           `json:"expiry_fields"`
	ExpiryWarningDays   int                `json:"expiry_warning_days"`
	DelegationLabels    []string           `json:"delegation_labels"`
	StaleRecordDays     int                `json:"stale_record_days"`
	ClaimableServices   []claimableService `json:"claimable_services"`
}

var loadDanglingRules = sync.OnceValue(func() danglingRules {
	var r danglingRules
	if err := graph.DecodeStrict(danglingJSON, &r); err != nil {
		panic("dangling_dns.json: " + err.Error())
	}
	if r.RegistrationPurpose == "" || len(r.ExpiryFields) == 0 || r.StaleRecordDays < 1 {
		panic("dangling_dns.json: registration_purpose, expiry_fields and stale_record_days are required")
	}
	for i := range r.ClaimableServices {
		s := &r.ClaimableServices[i]
		if s.Service == "" || s.Source == "" || len(s.Patterns) == 0 {
			panic("dangling_dns.json: every claimable service needs a service, patterns and a source")
		}
		for _, p := range s.Patterns {
			s.res = append(s.res, regexp.MustCompile(p))
		}
	}

	return r
})

// danglingNow is the clock registrations are compared with; tests replace it.
var danglingNow = time.Now

// underscoredName reports whether name is an RFC 8552 "underscored" DNS name —
// one with a label that begins with "_", such as a DKIM selector
// (selector1._domainkey.example.com), _dmarc, _acme-challenge, or an SRV name
// (_sip._tcp.example.com). These names carry TXT/SRV/other records rather than
// addresses, so an alias of one resolving to no A record is expected, not a
// dangling host or a takeover candidate.
func underscoredName(name string) bool {
	for _, label := range strings.Split(strings.ToLower(name), ".") {
		if strings.HasPrefix(label, "_") {
			return true
		}
	}
	return false
}

// claimable returns the service whose resources name is one of.
func claimable(name string) (claimableService, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, s := range loadDanglingRules().ClaimableServices {
		for _, re := range s.res {
			if re.MatchString(name) {
				return s, true
			}
		}
	}

	return claimableService{}, false
}

// FindDanglingDNS walks the controlled footprint of a domain or
// organization, as the vendors lens does, and reports the DNS records of its
// names that may point at something it no longer holds: aliases to names
// with no stored address (on a service where anyone can claim them, or
// elsewhere), alias chains that loop, aliases and name servers in domains
// whose registration has expired or is about to, and address records
// outside its networks not seen again since. These are leads from stored
// records, to be checked with a live lookup. It reads only.
func FindDanglingDNS(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (DanglingReport, error) {
	out := DanglingReport{Root: root}
	meaning := graph.MeaningsOf(schema)
	if schema == nil || meaning == nil {
		return out, errors.New("the dangling DNS lens requires relationship semantics")
	}
	bounded, ok := g.(graph.BoundedGraph)
	if !ok {
		return out, errors.New("bounded graph reader required")
	}
	if err := limits.Validate(); err != nil {
		return out, err
	}

	report := ThirdPartyReport{Root: root, FootprintTypes: map[string]int{}}
	w := newLensWalker(ctx, g, bounded, meaning, schema.Relations(), root, &report)
	w.maxAssets, w.maxReads = limits.assets(), limits.reads()
	roots := []graph.Asset{root}
	owners, err := w.owningOrganizations(root)
	if err != nil {
		return out, err
	}
	for _, o := range owners {
		out.Owners = append(out.Owners, graph.AssetLabel(o))
		roots = append(roots, o)
	}

	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return out, err
	}
	out.Footprint = len(owned)

	s := danglingScan{w: w, g: g, owned: owned, ownDomains: map[string]bool{}, expiry: map[string]*time.Time{},
		seen: map[string]bool{}}
	for _, id := range order {
		a := owned[id]
		switch a.Type {
		case "FQDN":
			s.ownDomains[graph.RegisteredDomain(graph.FQDNName(a))] = true
		case "Netblock":
			if p, err := netip.ParsePrefix(graph.ContentString(a, "cidr")); err == nil {
				s.ownNets = append(s.ownNets, p.Masked())
			}
		}
	}

	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if report.Reads >= w.maxReads {
			w.truncate("database read limit")
			break
		}

		a := owned[id]
		if a.Type != "FQDN" && a.Type != "DomainRecord" {
			continue
		}
		if a.Type == "FQDN" {
			out.Names++
			if err := s.name(a); err != nil {
				return out, err
			}
		}
		if err := s.delegations(a); err != nil {
			return out, err
		}
	}

	out.Findings = s.findings
	rank := map[string]int{}
	for i, k := range danglingOrder {
		rank[k] = i
	}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if rank[a.Kind] != rank[b.Kind] {
			return rank[a.Kind] < rank[b.Kind]
		}
		return a.Name < b.Name
	})
	out.Reads = report.Reads
	out.Truncated, out.Reason = report.Truncated, report.Reason
	return out, nil
}

type danglingScan struct {
	w          *lensWalker
	g          graph.Graph
	owned      map[string]graph.Asset
	ownDomains map[string]bool
	ownNets    []netip.Prefix
	// expiry caches each registered domain's stored expiry, nil when none.
	expiry   map[string]*time.Time
	seen     map[string]bool
	findings []DanglingFinding
}

func (s *danglingScan) add(f DanglingFinding) {
	key := f.Kind + "\x00" + f.NameID + "\x00" + f.Target
	if !s.seen[key] {
		s.seen[key] = true
		s.findings = append(s.findings, f)
	}
}

// name checks one of the subject's names: its alias chain and its
// address records.
func (s *danglingScan) name(a graph.Asset) error {
	res, err := resolveName(s.w, a)
	if err != nil {
		return err
	}

	name := graph.FQDNName(a)
	var via []string
	for _, x := range res.Aliases {
		via = append(via, graph.FQDNName(x))
	}
	target := graph.FQDNName(res.Target(a))

	// Confirmed bucket takeover: a CNAME to an object-storage bucket host whose
	// stored bucket a probe found missing (NoSuchBucket) is claimable even when
	// the host still resolves to the provider's endpoint, which the
	// no-address check below misses. Reads the StorageBucket on the target's
	// "bucket" relation.
	if res.Aliased() && !underscoredName(name) && !s.ownDomains[graph.RegisteredDomain(target)] {
		if prov, _, ok := semantics.MatchBucketHost(target); ok {
			sb, found, err := storedBucket(s.w, res.Target(a))
			if err != nil {
				return err
			}
			if found && !bucketExists(sb) {
				s.add(DanglingFinding{Kind: DanglingClaimable, Name: name, NameID: a.ID, Target: target, Via: via,
					Service: prov.Organization + " bucket", Source: prov.Source,
					Detail: fmt.Sprintf("alias to the %s bucket %q, which a probe found does not exist "+
						"(NoSuchBucket); anyone can create it and serve content as %s", prov.Organization, target, name)})
			}
		}
	}

	switch {
	case res.Loop || res.Deep:
		s.add(DanglingFinding{Kind: DanglingLoop, Name: name, NameID: a.ID, Target: target, Via: via,
			Detail: "the alias chain returns to a name already in it or exceeds the resolver depth limit"})
	case res.Aliased() && len(res.Addresses) == 0 && !s.ownDomains[graph.RegisteredDomain(target)] &&
		!underscoredName(name):
		if svc, ok := claimable(target); ok {
			s.add(DanglingFinding{Kind: DanglingClaimable, Name: name, NameID: a.ID, Target: target, Via: via,
				Service: svc.Service, Source: svc.Source,
				Detail: fmt.Sprintf("alias to a %s name with no stored address; if the resource was deleted, "+
					"anyone can claim the name and serve content as %s", svc.Service, name)})
		} else {
			s.add(DanglingFinding{Kind: DanglingUnresolved, Name: name, NameID: a.ID, Target: target, Via: via,
				Detail: "alias to an outside name with no stored address"})
		}
	}

	// Every outside domain in the chain must still be registered.
	for _, x := range res.Aliases {
		if err := s.checkExpiry(a, graph.FQDNName(x), via, "alias target"); err != nil {
			return err
		}
	}

	return s.staleAddresses(a)
}

// delegations checks the name servers a name or registration delegates to.
func (s *danglingScan) delegations(a graph.Asset) error {
	rules := loadDanglingRules()
	steps, err := s.w.steps(a)
	if err != nil {
		return err
	}

	for _, st := range steps {
		if !st.forward || st.other.Type != "FQDN" ||
			(!delegationRR(st.edge) && !slices.Contains(rules.DelegationLabels, st.edge.Label)) {
			continue
		}
		if err := s.checkExpiry(a, graph.FQDNName(st.other), nil, "name server"); err != nil {
			return err
		}
	}

	return nil
}

// checkExpiry reports target when its registered domain, outside the
// subject's, has a stored registration that expired or expires soon.
func (s *danglingScan) checkExpiry(from graph.Asset, target string, via []string, role string) error {
	domain := graph.RegisteredDomain(target)
	if domain == "" || s.ownDomains[domain] {
		return nil
	}

	exp, err := s.domainExpiry(domain)
	if err != nil || exp == nil {
		return err
	}

	rules := loadDanglingRules()
	now := danglingNow()
	name := graph.AssetLabel(from)
	if from.Type == "FQDN" {
		name = graph.FQDNName(from)
	}
	switch {
	case exp.Before(now):
		s.add(DanglingFinding{Kind: DanglingExpired, Name: name, NameID: from.ID, Target: target, Via: via,
			Detail: fmt.Sprintf("%s in %s, whose stored registration expired %s; anyone may register it",
				role, domain, exp.Format("2006-01-02"))})
	case rules.ExpiryWarningDays > 0 && exp.Before(now.AddDate(0, 0, rules.ExpiryWarningDays)):
		s.add(DanglingFinding{Kind: DanglingExpiring, Name: name, NameID: from.ID, Target: target, Via: via,
			Detail: fmt.Sprintf("%s in %s, whose stored registration expires %s", role, domain,
				exp.Format("2006-01-02"))})
	}

	return nil
}

// domainExpiry returns the expiry stored in a registered domain's
// registration record, or nil when none is stored.
func (s *danglingScan) domainExpiry(domain string) (*time.Time, error) {
	if exp, ok := s.expiry[domain]; ok {
		return exp, nil
	}
	s.expiry[domain] = nil

	resolver, ok := s.g.(graph.AssetResolver)
	if !ok {
		return nil, nil
	}
	res, err := resolver.ResolveAsset(s.w.ctx, graph.AssetSelector{Type: "FQDN", Field: "name", Value: domain}, 2)
	if err != nil || len(res.Candidates) == 0 {
		return nil, nil
	}

	rules := loadDanglingRules()
	steps, err := s.w.steps(res.Candidates[0].Asset)
	if err != nil {
		return nil, err
	}
	for _, st := range steps {
		if !st.forward || st.purpose != rules.RegistrationPurpose {
			continue
		}
		for _, f := range rules.ExpiryFields {
			if t, ok := parseRecordDate(graph.ContentString(st.other, f)); ok {
				s.expiry[domain] = &t
				return &t, nil
			}
		}
	}

	return nil, nil
}

// parseRecordDate reads the dates registration records store.
func parseRecordDate(v string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, strings.TrimSpace(v)); err == nil {
			return t, true
		}
	}

	return time.Time{}, false
}

// staleAddresses reports the name's address records outside the subject's
// networks that were not seen again within stale_record_days of the last
// time the name was seen.
func (s *danglingScan) staleAddresses(a graph.Asset) error {
	if a.LastSeen.IsZero() {
		return nil
	}

	rules := loadDanglingRules()
	dns := loadDNSRules()
	steps, err := s.w.steps(a)
	if err != nil {
		return err
	}
	for _, st := range steps {
		if !st.forward || st.purpose != dns.DNSPurpose || !slices.Contains(dns.AddressTypes, st.other.Type) ||
			st.edge.LastSeen.IsZero() {
			continue
		}
		if a.LastSeen.Sub(st.edge.LastSeen) < time.Duration(rules.StaleRecordDays)*24*time.Hour {
			continue
		}
		addr, err := netip.ParseAddr(graph.ContentString(st.other, "address"))
		if err == nil && slices.ContainsFunc(s.ownNets, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			continue
		}

		s.add(DanglingFinding{Kind: DanglingStale, Name: graph.FQDNName(a), NameID: a.ID,
			Target: graph.AssetLabel(st.other),
			Detail: fmt.Sprintf("address record last seen %s, the name last seen %s; the address may have been "+
				"released to someone else", st.edge.LastSeen.Format("2006-01-02"), a.LastSeen.Format("2006-01-02"))})
	}

	return nil
}

// FormatDanglingReport renders the dangling DNS lens for a terminal.
func FormatDanglingReport(r DanglingReport) string {
	var b strings.Builder
	scope := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		scope += " and " + strings.Join(r.Owners, ", ")
	}
	fmt.Fprintf(&b, "Dangling DNS of %s: %d name(s) checked from %d controlled asset(s) (%d reads).\n", scope,
		r.Names, r.Footprint, r.Reads)

	if len(r.Findings) == 0 {
		b.WriteString("No stored record points at something it may no longer hold.\n")
	}
	titles := map[string]string{
		DanglingClaimable:  "Aliases to claimable service names with no stored address (possible subdomain takeover)",
		DanglingExpired:    "Aliases and name servers in domains whose registration expired",
		DanglingExpiring:   "Aliases and name servers in domains whose registration expires soon",
		DanglingUnresolved: "Aliases to outside names with no stored address",
		DanglingLoop:       "Alias chains that loop or never end",
		DanglingStale:      "Address records not seen again (the address may have been released)",
	}
	for _, kind := range danglingOrder {
		var lines []string
		for _, f := range r.Findings {
			if f.Kind != kind {
				continue
			}
			line := fmt.Sprintf("  %s -> %s", f.Name, f.Target)
			if len(f.Via) > 1 {
				line = fmt.Sprintf("  %s -> %s", f.Name, strings.Join(f.Via, " -> "))
			}
			line += ": " + f.Detail
			if f.Source != "" {
				line += " (" + f.Source + ")"
			}
			lines = append(lines, line)
		}
		if len(lines) > 0 {
			fmt.Fprintf(&b, "\n%s (%d):\n%s\n", titles[kind], len(lines), strings.Join(lines, "\n"))
		}
	}

	b.WriteString("These come from stored records, not a live lookup; confirm each before acting.")
	if r.Truncated {
		fmt.Fprintf(&b, " Results are partial (%s); raise -max-assets or -max-reads to cover more.", r.Reason)
	}
	b.WriteString("\n")
	return b.String()
}
