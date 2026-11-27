// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

var familyJSON = semantics.File("family.json")

type familyRules struct {
	License         string   `json:"_license"`
	About           string   `json:"_about"`
	DepartmentWords []string `json:"department_words"`
	UnitNouns       []string `json:"unit_nouns"`
	// GenericWords are semantics.OrgGenericWords (org_names.json).
	GenericWords   []string `json:"-"`
	SampleNames    int      `json:"sample_names"`
	SampleNetwork  int      `json:"sample_network"`
	RenameWords    []string `json:"rename_words"`
	MinHostedNames int      `json:"min_hosted_names"`
	DedicatedShare float64  `json:"dedicated_share"`
}

// familyStrongTie is the weight of a registration, or of a name that is the
// domain's, when choosing the domain's main organization.
const familyStrongTie = 5

var loadFamilyRules = sync.OnceValue(func() familyRules {
	var r familyRules
	if err := graph.DecodeStrict(familyJSON, &r); err != nil {
		panic("family.json: " + err.Error())
	}
	if r.SampleNames < 1 || r.SampleNetwork < 1 || r.SampleNames > graph.MaxEdgeRead ||
		r.SampleNetwork > graph.MaxEdgeRead ||
		r.DedicatedShare <= 0 || r.DedicatedShare > 1 {
		panic("family.json: sample sizes must be in 1..500 and dedicated_share in (0, 1]")
	}
	r.GenericWords = semantics.OrgGenericWords()

	return r
})

var relationTable = sync.OnceValues(semantics.Load)

// Family relations.
const (
	FamilySame       = "same_institution"
	FamilyDepartment = "department"
	FamilyAffiliate  = "affiliate"
	// FamilyOther is an organization on the domain's assets that is not
	// family by name or registration, such as a hosting provider or a
	// vendor named on a certificate.
	FamilyOther = "other"
)

// FamilyMember is an organization tied to the domain, how it relates to
// the domain's main organization, and the evidence.
type FamilyMember struct {
	Organization graph.Asset `json:"organization"`
	Relation     string      `json:"relation"`
	Evidence     []string    `json:"evidence"`
	// ByName reports that a same-institution member's name is a variant of
	// another's; only those are proposed for merging.
	ByName bool `json:"by_name,omitempty"`
}

// FamilyNetwork is a network that serves the domain's names.
type FamilyNetwork struct {
	CIDR      string `json:"cidr"`
	Holder    string `json:"holder,omitempty"`
	HolderID  string `json:"holder_id,omitempty"`
	Names     int    `json:"names"`
	Dedicated bool   `json:"dedicated"`
	// Share is the fraction of the names sampled from the network that are
	// the domain's.
	Share float64 `json:"share"`
}

// RelatedDomain is a registered domain served by the family's dedicated
// networks.
type RelatedDomain struct {
	Domain string `json:"domain"`
	Names  int    `json:"names"`
	CIDR   string `json:"cidr"`
	// OwnNetwork reports that the institution itself (not an affiliate)
	// holds the network. Own reports that the domain is also the
	// institution's by evidence of control: one of its organizations
	// registered it, or the domain's label spells one of their names. A
	// domain on the institution's network without that evidence is only
	// hosted there, as a hosting company's customers are.
	OwnNetwork bool `json:"own_network,omitempty"`
	Own        bool `json:"own,omitempty"`
}

// FamilyReport is the result of the organization family lens.
type FamilyReport struct {
	Domain         string          `json:"domain"`
	Main           *graph.Asset    `json:"main,omitempty"`
	Members        []FamilyMember  `json:"members"`
	Networks       []FamilyNetwork `json:"networks"`
	RelatedDomains []RelatedDomain `json:"related_domains"`
	SampledNames   int             `json:"sampled_names"`
	// MoreNames reports that the domain has more names than were sampled.
	MoreNames bool   `json:"more_names,omitempty"`
	Reads     int    `json:"reads"`
	Truncated bool   `json:"truncated"`
	Reason    string `json:"reason,omitempty"`
}

// familyProfile adds to an organization's profile what it controls.
type familyProfile struct {
	*orgProfile
	// registers are domains it is a controlling registration contact for;
	// contactFor those it is another registration contact for.
	registers  map[string]bool
	contactFor map[string]bool
	// certified counts the certificates naming it, by registered domain.
	certified map[string]int
	emails    map[string]bool
	netRecs   map[string]bool
	autnums   map[string]bool
}

type familySearch struct {
	dup      *dupSearch
	rules    familyRules
	table    *semantics.Table
	report   FamilyReport
	profiles map[string]*familyProfile
	// holders maps a netblock to the organizations holding it.
	holders  map[string][]string
	cidrs    map[string]string
	netNames map[string]int
	// skipped are organizations reached but not profiled (placeholders).
	skipped map[string]bool
	// tied are the organizations tied to the domain, set once members are
	// classified.
	tied map[string]bool
	// heldNames counts, for each organization holding a network, the
	// sampled names resolving into any network it holds.
	heldNames map[string]map[string]bool
}

// FindOrganizationFamily finds the organizations tied to an enumerated
// domain, classifies each as the same institution, a department or an
// affiliate of the domain's main organization, and lists the networks and
// registered domains that serve them. root is the domain's FQDN asset. It
// reads only.
func FindOrganizationFamily(ctx context.Context, g graph.Graph, root graph.Asset) (FamilyReport, error) {
	table, err := relationTable()
	if err != nil {
		return FamilyReport{}, err
	}

	domain := strings.ToLower(strings.TrimSuffix(graph.ContentString(root, "name"), "."))
	if domain == "" {
		domain = strings.ToLower(root.Key)
	}

	s := &familySearch{dup: &dupSearch{ctx: ctx, graph: g, profiles: map[string]*orgProfile{}},
		rules: loadFamilyRules(), table: table, report: FamilyReport{Domain: domain},
		profiles: map[string]*familyProfile{}, holders: map[string][]string{}, cidrs: map[string]string{},
		netNames: map[string]int{}, heldNames: map[string]map[string]bool{}, skipped: map[string]bool{}}
	if err := s.discoverRegistrants(root); err != nil {
		return s.finish(), err
	}
	if err := s.sampleDomain(root); err != nil {
		return s.finish(), err
	}

	direct := s.directTies(domain)
	dedicated, sampled, err := s.classifyNetworks(domain, direct)
	if err != nil {
		return s.finish(), err
	}

	s.members(domain, direct, dedicated)
	s.memberNetworks(domain, dedicated)
	s.relatedDomains(domain, dedicated, sampled)
	s.providerNetworks()
	return s.finish(), nil
}

// finish completes the report with what the search read.
func (s *familySearch) finish() FamilyReport {
	s.report.Reads = s.dup.report.Reads
	if s.dup.report.Truncated {
		s.truncate(s.dup.report.Reason)
	}

	return s.report
}

func (s *familySearch) truncate(reason string) {
	truncateOnce(&s.report.Truncated, &s.report.Reason, reason)
}

// The search reads outward from the domain: its registration contacts,
// the subjects of certificates for its sampled names and the holders of
// the networks those names resolve into. Only the organizations reached
// are profiled, so the cost follows the domain's records, not the number
// of organizations stored.

// discoverRegistrants profiles the organizations named by the domain's
// registration records.
func (s *familySearch) discoverRegistrants(root graph.Asset) error {
	regs, err := s.dup.edges(root.ID, "out", "registration")
	if err != nil {
		return err
	}
	for _, r := range regs {
		orgs, err := s.recordOrganizations(r.ToID, false)
		if err != nil {
			return err
		}
		for _, id := range orgs {
			if err := s.profileOrganization(id); err != nil {
				return err
			}
		}
	}

	return nil
}

// discoverCertificates profiles the subjects of the certificates whose
// common name is the given name.
func (s *familySearch) discoverCertificates(nameID string) error {
	certs, err := s.dup.edges(nameID, "in", "common_name")
	if err != nil {
		return err
	}
	for _, c := range certs {
		orgs, err := s.recordOrganizations(c.FromID, true)
		if err != nil {
			return err
		}
		for _, id := range orgs {
			if err := s.profileOrganization(id); err != nil {
				return err
			}
		}
	}

	return nil
}

// recordOrganizations returns the organizations named by the contact
// records a record (a domain, network, AS or certificate record) points
// at; with controllers set, only the contacts the semantics table marks as
// controlling it.
func (s *familySearch) recordOrganizations(recID string, controllers bool) ([]string, error) {
	rec, err := s.dup.asset(recID)
	if err != nil {
		return nil, err
	}

	out, err := s.dup.edges(recID, "out", "")
	if err != nil {
		return nil, err
	}

	var orgs []string
	for _, e := range out {
		cr, err := s.dup.asset(e.ToID)
		if err != nil {
			return nil, err
		}
		if cr.Type != "ContactRecord" {
			continue
		}
		if controllers {
			m, ok := s.table.Lookup(rec.Type, e.Label, e.Type, cr.Type)
			if !ok || m.Attribution != semantics.Controller {
				continue
			}
		}

		named, err := s.dup.edges(cr.ID, "out", "organization")
		if err != nil {
			return nil, err
		}
		for _, n := range named {
			if !slices.Contains(orgs, n.ToID) {
				orgs = append(orgs, n.ToID)
			}
		}
	}

	return orgs, nil
}

// profileOrganization profiles an organization reached from the domain, and
// what it controls, once. Placeholders are skipped.
func (s *familySearch) profileOrganization(id string) error {
	if _, ok := s.profiles[id]; ok || s.skipped[id] {
		return nil
	}
	o, err := s.dup.asset(id)
	if err != nil {
		return err
	}
	if o.Type != "Organization" || graph.IsPlaceholder(o) ||
		semantics.IsPlaceholderOrganization(graph.ContentString(o, "name")) {
		s.skipped[id] = true
		return nil
	}

	p, err := s.dup.profile(o)
	if err != nil {
		return err
	}

	fp := &familyProfile{orgProfile: p, registers: map[string]bool{}, contactFor: map[string]bool{},
		certified: map[string]int{}, emails: map[string]bool{}, netRecs: map[string]bool{}, autnums: map[string]bool{}}
	if err := s.controls(fp); err != nil {
		return err
	}

	s.profiles[id] = fp
	return nil
}

// controls reads what points at the organization's contact records: the
// registrations, certificates and network records it is named on.
func (s *familySearch) controls(p *familyProfile) error {
	for cr := range p.contacts {
		in, err := s.dup.edges(cr, "in", "")
		if err != nil {
			return err
		}
		for _, e := range in {
			if e.Label == "organization" {
				continue
			}

			src, err := s.dup.asset(e.FromID)
			if err != nil {
				return err
			}

			meaning, ok := s.table.Lookup(src.Type, e.Label, e.Type, "ContactRecord")
			controller := ok && meaning.Attribution == semantics.Controller
			switch src.Type {
			case "DomainRecord":
				if d := strings.ToLower(graph.ContentString(src, "domain")); d != "" {
					if controller {
						p.registers[d] = true
					} else {
						p.contactFor[d] = true
					}
				}
			case "TLSCertificate":
				if cn := graph.ContentString(src, "subject_common_name"); controller && cn != "" {
					p.certified[graph.RegisteredDomain(strings.TrimPrefix(cn, "*."))]++
				}
			case "IPNetRecord":
				if controller {
					p.netRecs[src.ID] = true
				}
			case "AutnumRecord":
				if controller {
					p.autnums[src.ID] = true
				}
			}
		}

		ids, err := s.dup.edges(cr, "out", "id")
		if err != nil {
			return err
		}
		for _, e := range ids {
			a, err := s.dup.asset(e.ToID)
			if err != nil {
				return err
			}
			if strings.EqualFold(graph.ContentString(a, "id_type"), "email") {
				if _, dom, ok := strings.Cut(graph.ContentString(a, "id"), "@"); ok && dom != "" {
					p.emails[graph.RegisteredDomain(dom)] = true
				}
			}
		}
	}

	return nil
}

// sampleDomain walks the domain's names and counts how many resolve into
// each network.
func (s *familySearch) sampleDomain(root graph.Asset) error {
	queue := []string{root.ID}
	seen := map[string]bool{root.ID: true}
	for len(queue) > 0 && s.report.SampledNames < s.rules.SampleNames {
		id := queue[0]
		queue = queue[1:]
		s.report.SampledNames++

		if err := s.discoverCertificates(id); err != nil {
			return err
		}
		if err := s.countNameNetblocks(id, s.netNames); err != nil {
			return err
		}

		children, err := s.dup.firstEdges(id, "out", "node", graph.MaxEdgeRead)
		if err != nil {
			return err
		}
		for _, c := range children {
			if !seen[c.ToID] {
				seen[c.ToID] = true
				queue = append(queue, c.ToID)
			}
		}
	}

	s.report.MoreNames = len(queue) > 0

	return nil
}

// FormatFamilyReport renders a family report for a terminal.
func FormatFamilyReport(r FamilyReport) string {
	var b strings.Builder
	more := ""
	if r.MoreNames {
		more = "; it has more"
	}

	fmt.Fprintf(&b, "Organization family of %s (%d of its names sampled%s, %d reads).", r.Domain, r.SampledNames,
		more, r.Reads)
	if r.Truncated {
		fmt.Fprintf(&b, " Incomplete: %s.", r.Reason)
	}

	b.WriteString("\n")
	if r.Main == nil {
		b.WriteString("No stored organization is tied to the domain.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "Main organization: %s [%s]\n", graph.AssetLabel(*r.Main), r.Main.ID)
	titles := map[string]string{FamilySame: "Same institution", FamilyDepartment: "Departments",
		FamilyAffiliate: "Affiliates", FamilyOther: "Other organizations on its assets (providers and vendors)"}
	last := ""
	for _, m := range r.Members {
		if m.Relation != last {
			fmt.Fprintf(&b, "\n%s:\n", titles[m.Relation])
			last = m.Relation
		}

		fmt.Fprintf(&b, "  %s [%s]\n", graph.AssetLabel(m.Organization), m.Organization.ID)
		for _, e := range m.Evidence {
			fmt.Fprintf(&b, "    - %s\n", e)
		}
	}

	if len(r.Networks) > 0 {
		b.WriteString("\nNetworks serving its names:\n")
		for _, n := range r.Networks {
			kind := "provider"
			if n.Dedicated {
				kind = "the family's"
			}

			holder := n.Holder
			if holder == "" {
				holder = "holder unknown"
			}

			fmt.Fprintf(&b, "  %s (%s): %d of the sampled names, %s, %.0f%% of the names stored for it are the "+
				"domain's\n", n.CIDR, holder, n.Names, kind, n.Share*100)
		}
	}
	if len(r.RelatedDomains) > 0 {
		b.WriteString("\nOther registered domains on the family's networks:\n")
		for _, d := range r.RelatedDomains {
			whose := ""
			switch {
			case d.Own:
				whose = ", the institution's own"
			case d.OwnNetwork:
				whose = ", hosted on the institution's network"
			}

			fmt.Fprintf(&b, "  %s (%d names, %s%s)\n", d.Domain, d.Names, d.CIDR, whose)
		}
	}

	return b.String()
}
