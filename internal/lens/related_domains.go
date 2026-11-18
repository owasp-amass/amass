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
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/registrant"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Horizontal correlation associates more registered (apex) domains with a
// target organization, so an enumeration's scope can be made more complete.
// This read-only lens is the first, safe half: it surfaces the apex domains the
// horizontal signals tie to an organization, each with the evidence and a
// confidence, for a person (or the review-gated scope expansion) to decide on —
// it never grows scope itself (ai-design-principles.md, principles 10 & 13).
//
// The signals, each weak on its own (principle 8) and accumulated per domain:
//   - shared registrant organization: another domain whose WHOIS/RDAP
//     registrant contact names the same organization;
//   - shared certificate subject organization: a TLS certificate whose subject
//     contact names the organization, and the apex domains it covers (its
//     common name and DNS SANs), skipping a shared/CDN certificate that covers
//     many unrelated apexes.
//
// A WHOIS privacy proxy or a placeholder organization is shared by many
// unrelated domains, so such a subject is never correlated on. Further signals
// (shared name servers, MX, dedicated IP) extend the same accumulation.

const (
	// relatedMaxContacts bounds the contact records read for one organization.
	relatedMaxContacts = 200
	// relatedMaxCerts bounds the certificates read per contact record.
	relatedMaxCerts = 500
	// relatedMaxDomains bounds the domains one search returns.
	relatedMaxDomains = 2000
	// certMaxApexes skips a certificate that covers more distinct apex domains
	// than this: a shared or CDN certificate spanning many tenants is not
	// evidence that those tenants share an owner (principle 8).
	certMaxApexes = 25
	// relatedRegistrantConfidence and relatedCertConfidence weight the two
	// signals: real evidence, but a human confirms before scope grows.
	relatedRegistrantConfidence = 70
	relatedCertConfidence       = 75
)

// HorizontalDomain is a registered (apex) domain a horizontal signal ties to
// the subject organization, with the evidence and confidence behind it.
type HorizontalDomain struct {
	Domain     string              `json:"domain"`
	Confidence int                 `json:"confidence"`
	Signals    []string            `json:"signals"`
	Witness    []graph.WitnessEdge `json:"witness,omitempty"`
}

// RelatedDomainsReport is the result of a horizontal related-domain search for
// one organization.
type RelatedDomainsReport struct {
	OrgID     string             `json:"org_id"`
	Org       string             `json:"org"`
	Domains   []HorizontalDomain `json:"domains"`
	Truncated string             `json:"truncated,omitempty"`
}

// FindRelatedDomains finds the registered domains the horizontal signals tie to
// an organization, read-only. It returns nothing for a privacy proxy or a
// placeholder organization, which many unrelated domains share (principle 8).
func FindRelatedDomains(ctx context.Context, g graph.Graph, orgID string) (RelatedDomainsReport, error) {
	org, err := g.GetAsset(ctx, orgID)
	if err != nil {
		return RelatedDomainsReport{}, err
	}
	if org.Type != "Organization" {
		return RelatedDomainsReport{}, fmt.Errorf("%s is not an Organization", orgID)
	}

	name := graph.ContentString(org, "name")
	report := RelatedDomainsReport{OrgID: orgID, Org: name}

	// Never correlate on a privacy proxy or a placeholder organization.
	if name == "" || registrant.IsPrivacyProxyName(name) || semantics.IsPlaceholderOrganization(name) {
		return report, nil
	}

	acc := map[string]*HorizontalDomain{}
	add := func(apex string, confidence int, signal string, witness ...graph.WitnessEdge) bool {
		apex = strings.ToLower(strings.TrimSpace(apex))
		if apex == "" {
			return true
		}
		d, ok := acc[apex]
		if !ok {
			if len(acc) >= relatedMaxDomains {
				report.Truncated = fmt.Sprintf("more than %d domains", relatedMaxDomains)
				return false
			}
			d = &HorizontalDomain{Domain: apex}
			acc[apex] = d
		}
		if confidence > d.Confidence {
			d.Confidence = confidence
		}
		if !slices.Contains(d.Signals, signal) {
			d.Signals = append(d.Signals, signal)
		}
		d.Witness = append(d.Witness, witness...)
		return true
	}

	// ContactRecord --organization--> Organization: the contacts naming this org.
	contacts, err := g.Edges(ctx, orgID, "in", "organization", time.Time{})
	if err != nil {
		return report, err
	}

	registrantSig := "shared registrant organization: " + name
	certSig := "shared certificate subject organization: " + name
	orgWitness := func(ce graph.Relation) graph.WitnessEdge {
		return graph.WitnessEdge{EdgeID: ce.ID, Label: "organization", RelationType: ce.Type,
			FromID: ce.FromID, FromType: "ContactRecord", ToID: ce.ToID, ToType: "Organization", To: name}
	}

contacts:
	for i, ce := range contacts {
		if i >= relatedMaxContacts {
			report.Truncated = fmt.Sprintf("more than %d contact records", relatedMaxContacts)
			break
		}

		// DomainRecord --registrant_contact--> ContactRecord.
		drs, err := g.Edges(ctx, ce.FromID, "in", "registrant_contact", time.Time{})
		if err != nil {
			return report, err
		}
		for _, de := range drs {
			dr, err := g.GetAsset(ctx, de.FromID)
			if err != nil {
				continue
			}
			w := graph.WitnessEdge{EdgeID: de.ID, Label: "registrant_contact", RelationType: de.Type,
				FromID: de.FromID, FromType: "DomainRecord", ToID: de.ToID, ToType: "ContactRecord"}
			if !add(graph.ContentString(dr, "domain"), relatedRegistrantConfidence, registrantSig, w, orgWitness(ce)) {
				break contacts
			}
		}

		// TLSCertificate --subject_contact--> ContactRecord.
		certs, err := g.Edges(ctx, ce.FromID, "in", "subject_contact", time.Time{})
		if err != nil {
			return report, err
		}
		for j, cte := range certs {
			if j >= relatedMaxCerts {
				break
			}
			apexes := certApexes(ctx, g, cte.FromID)
			if len(apexes) == 0 || len(apexes) > certMaxApexes {
				continue // unresolved, or a shared/CDN certificate
			}
			certW := graph.WitnessEdge{EdgeID: cte.ID, Label: "subject_contact", RelationType: cte.Type,
				FromID: cte.FromID, FromType: "TLSCertificate", ToID: cte.ToID, ToType: "ContactRecord"}
			for _, apex := range sortedRelationKeys(apexes) {
				fq := apexes[apex]
				sanW := graph.WitnessEdge{EdgeID: fq.ID, Label: fq.Label, RelationType: fq.Type,
					FromID: fq.FromID, FromType: "TLSCertificate", ToID: fq.ToID, ToType: "FQDN", To: apex}
				if !add(apex, relatedCertConfidence, certSig, certW, orgWitness(ce), sanW) {
					break contacts
				}
			}
		}
	}

	report.Domains = make([]HorizontalDomain, 0, len(acc))
	for _, d := range acc {
		report.Domains = append(report.Domains, *d)
	}
	sort.Slice(report.Domains, func(i, j int) bool { return report.Domains[i].Domain < report.Domains[j].Domain })
	return report, nil
}

// certApexes returns the apex (registered) domains a certificate covers — the
// registered domains of its common name and DNS SAN FQDNs — each mapped to one
// representative edge for the witness.
func certApexes(ctx context.Context, g graph.Graph, certID string) map[string]graph.Relation {
	out := map[string]graph.Relation{}
	for _, label := range []string{"common_name", "san_dns_name"} {
		edges, err := g.Edges(ctx, certID, "out", label, time.Time{})
		if err != nil {
			continue
		}
		for _, e := range edges {
			fq, err := g.GetAsset(ctx, e.ToID)
			if err != nil {
				continue
			}
			apex := graph.RegisteredDomain(graph.FQDNName(fq))
			if apex == "" {
				continue
			}
			if _, ok := out[apex]; !ok {
				out[apex] = e
			}
		}
	}

	return out
}

// FormatRelatedDomainsReport renders a related-domain search for a terminal.
func FormatRelatedDomainsReport(r RelatedDomainsReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Related domains for %s [%s]", r.Org, r.OrgID)
	if r.Truncated != "" {
		fmt.Fprintf(&b, " (truncated: %s)", r.Truncated)
	}
	b.WriteString("\n")
	if len(r.Domains) == 0 {
		b.WriteString("No related domains found.\n")
		return b.String()
	}
	for _, d := range r.Domains {
		fmt.Fprintf(&b, "  %s (confidence %d): %s\n", d.Domain, d.Confidence, strings.Join(d.Signals, ", "))
	}

	return b.String()
}
