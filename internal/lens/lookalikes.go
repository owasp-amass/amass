// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lookalike"
)

// LensLookalikes asks for registered domains that look like a domain's or
// organization's.
const LensLookalikes = "lookalike_domains"

var lookalikesLens = SubjectLens{
	Name:    LensLookalikes,
	Command: "lookalikes",
	Description: "List stored registered domains one typing mistake from a domain's or organization's, or under " +
		"another suffix, and whether each looks like its own or another party's. Read-only",
	Examples: []string{"Are there lookalike domains of <domain>?",
		"Has anyone registered typosquatting domains of <organization>?",
		"Which domains imitating <domain> can receive mail?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindLookalikes(ctx, g, schema, root, opts.Limits)
	},
}

// Who a lookalike seems to belong to.
const (
	// LookalikeOwn: it is in the subject's controlled footprint.
	LookalikeOwn = "own"
	// LookalikeOwnDNS: its name servers are on the subject's domains, as a
	// defensive registration's often are.
	LookalikeOwnDNS = "own_name_servers"
	// LookalikeOther: nothing stored ties it to the subject.
	LookalikeOther = "other"
)

// Lookalike is one stored registered domain that looks like a subject's.
type Lookalike struct {
	Domain   string   `json:"domain"`
	Imitates string   `json:"imitates"`
	Owner    string   `json:"owner"`
	Mail     bool     `json:"mail"`
	Hosts    []string `json:"name_server_hosts,omitempty"`
	// Registrant is the party its registration names, when one is stored.
	Registrant string `json:"registrant,omitempty"`
}

// LookalikeReport is the result of the lookalike domains lens.
type LookalikeReport struct {
	lensBase
	Domains    []string    `json:"domains"`
	Checked    int         `json:"checked"`
	Lookalikes []Lookalike `json:"lookalikes"`
	Sources    []string    `json:"sources"`
}

// FindLookalikes computes the lookalikes of root's registered domains, as
// the lookalike collection does, and reports those stored. It reads only.
func FindLookalikes(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (LookalikeReport, error) {
	var out LookalikeReport
	rules, err := lookalike.LoadRules()
	if err != nil {
		return out, err
	}

	out.Sources = []string{rules.TypoSource, rules.TLDSource}

	s, err := newScope(ctx, g, schema, root, limits, "lookalikes")
	if err != nil {
		return out, err
	}

	for d := range s.ownDomains {
		if _, _, ok := lookalike.Split(d); ok && !reservedName(d) {
			out.Domains = append(out.Domains, d)
		}
	}

	sort.Strings(out.Domains)

	seen := map[string]bool{}
	for _, d := range out.Domains {
		for _, c := range rules.Candidates(d) {
			if seen[c] {
				continue
			}

			seen[c] = true
			if s.spent() {
				break
			}

			s.report.Reads++
			out.Checked++
			a, ok := s.lookupName(c)
			if !ok {
				continue
			}

			l, err := s.lookalike(a, c, d)
			if err != nil {
				return out, err
			}

			out.Lookalikes = append(out.Lookalikes, l)
		}
	}

	rank := map[string]int{LookalikeOther: 0, LookalikeOwnDNS: 1, LookalikeOwn: 2}
	sort.SliceStable(out.Lookalikes, func(i, j int) bool {
		a, b := out.Lookalikes[i], out.Lookalikes[j]
		if rank[a.Owner] != rank[b.Owner] {
			return rank[a.Owner] < rank[b.Owner]
		}
		if a.Mail != b.Mail {
			return a.Mail
		}

		return a.Domain < b.Domain
	})
	out.lensBase = s.base()
	return out, nil
}

// lookalike reads what is stored about a lookalike: its name servers, mail
// servers and registrant, and whom it seems to belong to.
func (s *scope) lookalike(a graph.Asset, domain, imitates string) (Lookalike, error) {
	l := Lookalike{Domain: domain, Imitates: imitates, Owner: LookalikeOther}
	if _, own := s.owned[a.ID]; own {
		l.Owner = LookalikeOwn
	}

	steps, err := s.w.steps(a)
	if err != nil {
		return l, err
	}

	ownDNS := false
	rules := loadDomainRules()
	for _, st := range steps {
		if !st.forward {
			continue
		}
		switch {
		case mailRR(st.edge):
			l.Mail = true
		case delegationRR(st.edge):
			host := graph.FQDNName(st.other)
			graph.AddUnique(&l.Hosts, host)
			if s.ownDomains[graph.RegisteredDomain(host)] {
				ownDNS = true
			}
		case st.purpose == rules.RegistrationPurpose && l.Registrant == "":
			if name, own, err := s.registrantOf(st.other); err != nil {
				return l, err
			} else if name != "" {
				l.Registrant = name
				if own && l.Owner == LookalikeOther {
					l.Owner = LookalikeOwnDNS
				}
			}
		}
	}
	if ownDNS && l.Owner == LookalikeOther {
		l.Owner = LookalikeOwnDNS
	}

	sort.Strings(l.Hosts)
	return l, nil
}

// registrantOf names the party a registration record's registrant is, and
// whether it is the subject.
func (s *scope) registrantOf(rec graph.Asset) (string, bool, error) {
	steps, err := s.w.steps(rec)
	if err != nil {
		return "", false, err
	}
	for _, st := range steps {
		if st.forward && st.edge.Label == "registrant" {
			name, _, own, err := s.party(st.other)
			return name, own, err
		}
	}

	return "", false, nil
}

// Text implements Report.
func (r LookalikeReport) Text() string {
	var b strings.Builder
	others := 0
	for _, l := range r.Lookalikes {
		if l.Owner == LookalikeOther {
			others++
		}
	}

	fmt.Fprintf(&b, "Lookalike domains of %s: %d stored of %d checked for %d domain(s); %d not tied to it.\n",
		lookalikeSubject(r.Root, r.Owners), len(r.Lookalikes), r.Checked, len(r.Domains), others)
	if len(r.Lookalikes) == 0 {
		b.WriteString("\nNone stored. Lookalikes are collected during active enumeration of the domain.\n")
	}

	titles := map[string]string{LookalikeOther: "Not tied to it", LookalikeOwnDNS: "On its own name servers or registrant",
		LookalikeOwn: "In its own footprint"}
	for _, owner := range []string{LookalikeOther, LookalikeOwnDNS, LookalikeOwn} {
		var lines []string
		for _, l := range r.Lookalikes {
			if l.Owner != owner {
				continue
			}

			line := fmt.Sprintf("  %s (like %s)", l.Domain, l.Imitates)
			var notes []string
			if l.Mail {
				notes = append(notes, "receives mail")
			}
			if l.Registrant != "" {
				notes = append(notes, "registrant "+l.Registrant)
			}
			if len(l.Hosts) > 0 {
				notes = append(notes, "name servers "+strings.Join(l.Hosts, ", "))
			}
			if len(notes) > 0 {
				line += ": " + strings.Join(notes, "; ")
			}

			lines = append(lines, line)
		}
		if len(lines) > 0 {
			fmt.Fprintf(&b, "\n%s (%d):\n%s\n", titles[owner], len(lines), strings.Join(lines, "\n"))
		}
	}

	b.WriteString("\nOne insertion, deletion, adjacent-key substitution or transposition away, or another suffix " +
		"(Moore and Edelman's typo models). A lookalike is not necessarily hostile: many are defensive " +
		"registrations or unrelated names." + r.partialNote() + "\n")
	return b.String()
}

func lookalikeSubject(root graph.Asset, owners []string) string {
	label := graph.AssetLabel(root)
	if len(owners) > 0 {
		label += " and " + strings.Join(owners, ", ")
	}

	return label
}

// Facts implements Report: whom each lookalike seems to belong to, whether
// it receives mail, and its name.
func (r LookalikeReport) Facts() []string {
	out := make([]string, 0, len(r.Lookalikes))
	for _, l := range r.Lookalikes {
		kind := "lookalike_" + l.Owner
		if l.Owner == LookalikeOther && l.Mail {
			kind = "lookalike_mail"
		}

		out = append(out, kind+" "+l.Domain)
	}

	return out
}
