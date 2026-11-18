// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/registrant"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Horizontal correlation associates more registered (apex) domains with a
// target organization, so an enumeration's scope can be made more complete.
// This read-only lens is the first, safe half: it surfaces the apex domains a
// horizontal signal ties to an organization, each with the evidence and a
// confidence, for a person (or the review-gated scope expansion) to decide on —
// it never grows scope itself (ai-design-principles.md, principles 10 & 13).
//
// The first signal is a shared registrant organization: other domains whose
// WHOIS/RDAP registrant contact names the same organization. A single matching
// name is weak (principle 8), and a WHOIS privacy proxy or a placeholder
// organization is shared by many unrelated domains, so such a subject is never
// correlated on. Stronger, active signals (certificate O= / SAN clustering,
// shared infrastructure, web fingerprints) are added as further signals on the
// same report.

const (
	// relatedMaxContacts bounds the contact records read for one organization.
	relatedMaxContacts = 200
	// relatedMaxDomains bounds the domains one search returns.
	relatedMaxDomains = 2000
	// relatedRegistrantConfidence is the confidence for a domain tied to the
	// organization only by a shared registrant organization: real evidence, but
	// a human confirms before scope grows.
	relatedRegistrantConfidence = 70
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

// FindRelatedDomains finds the registered domains a horizontal signal ties to an
// organization, read-only. It returns nothing for a privacy proxy or a
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

	// ContactRecord --organization--> Organization: the contacts naming this org.
	contacts, err := g.Edges(ctx, orgID, "in", "organization", time.Time{})
	if err != nil {
		return report, err
	}

	seen := map[string]bool{}
	for i, ce := range contacts {
		if i >= relatedMaxContacts {
			report.Truncated = fmt.Sprintf("more than %d contact records", relatedMaxContacts)
			break
		}

		// DomainRecord --registrant_contact--> ContactRecord: domains registered
		// through this contact.
		drs, err := g.Edges(ctx, ce.FromID, "in", "registrant_contact", time.Time{})
		if err != nil {
			return report, err
		}
		for _, de := range drs {
			if len(report.Domains) >= relatedMaxDomains {
				report.Truncated = fmt.Sprintf("more than %d domains", relatedMaxDomains)
				break
			}

			dr, err := g.GetAsset(ctx, de.FromID)
			if err != nil {
				continue
			}
			domain := strings.ToLower(strings.TrimSpace(graph.ContentString(dr, "domain")))
			if domain == "" || seen[domain] {
				continue
			}
			seen[domain] = true

			report.Domains = append(report.Domains, HorizontalDomain{
				Domain:     domain,
				Confidence: relatedRegistrantConfidence,
				Signals:    []string{"shared registrant organization: " + name},
				Witness: []graph.WitnessEdge{
					{EdgeID: de.ID, Label: "registrant_contact", RelationType: de.Type,
						FromID: de.FromID, FromType: "DomainRecord", ToID: de.ToID, ToType: "ContactRecord"},
					{EdgeID: ce.ID, Label: "organization", RelationType: ce.Type,
						FromID: ce.FromID, FromType: "ContactRecord", ToID: ce.ToID, ToType: "Organization", To: name},
				},
			})
		}
	}

	sort.Slice(report.Domains, func(i, j int) bool { return report.Domains[i].Domain < report.Domains[j].Domain })
	return report, nil
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
