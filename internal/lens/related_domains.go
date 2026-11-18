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
//     common name and DNS SANs), skipping a shared/CDN certificate;
//   - shared name server: another domain served by the same name server as one
//     of the organization's own domains, skipping a shared/provider name server.
//   - official website: a domain the organization publishes as its own website
//     (e.g. recorded by the Wikidata official-website collector).
//
// A WHOIS privacy proxy or a placeholder organization is shared by many
// unrelated domains, so such a subject is never correlated on. A certificate or
// name server shared by more than a cap of distinct apexes is provider/CDN
// infrastructure, not shared ownership, and is skipped.

const (
	// relatedMaxContacts bounds the contact records read for one organization.
	relatedMaxContacts = 200
	// relatedMaxCerts bounds the certificates read per contact record.
	relatedMaxCerts = 500
	// relatedMaxDomains bounds the domains one search returns.
	relatedMaxDomains = 2000
	// certMaxApexes / nsMaxApexes skip a certificate or name server covering
	// more distinct apex domains than this: shared or CDN/provider
	// infrastructure spanning many tenants is not evidence of shared ownership
	// (principle 8).
	certMaxApexes = 25
	nsMaxApexes   = 25
)

// The per-signal confidences come from the horizontal signal catalog
// (internal/semantics/horizontal_signals.json), so the lens, the runtime
// scope-expansion decision and the classifier share one source of truth
// (principle 8). Each is the signal's catalog weight times 100.
var (
	relatedRegistrantConfidence = HorizontalConfidence(SigRegistrantOrg)
	relatedCertConfidence       = HorizontalConfidence(SigCertSubjectOrg)
	relatedNSConfidence         = HorizontalConfidence(SigSharedNameServer)
	relatedWebsiteConfidence    = HorizontalConfidence(SigOfficialWebsite)
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

// nsSibling is a domain record sharing a name server with the subject's own.
type nsSibling struct {
	apex string
	edge graph.Relation
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

	// ownDRs are the DomainRecords registered to this organization, the anchors
	// for the shared-name-server pivot.
	var ownDRs []string

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
			ownDRs = append(ownDRs, de.FromID)
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

	// Shared name server: domains served by the same non-provider name server
	// as one of the organization's own domains.
	seenNS := map[string]bool{}
nsPivot:
	for _, drID := range ownDRs {
		nsEdges, err := g.Edges(ctx, drID, "out", "name_server", time.Time{})
		if err != nil {
			continue
		}
		for _, nse := range nsEdges {
			if seenNS[nse.ToID] {
				continue
			}
			seenNS[nse.ToID] = true

			others, err := g.Edges(ctx, nse.ToID, "in", "name_server", time.Time{})
			if err != nil {
				continue
			}
			apexSet := map[string]bool{}
			var sibs []nsSibling
			for _, oe := range others {
				odr, err := g.GetAsset(ctx, oe.FromID)
				if err != nil {
					continue
				}
				apex := strings.ToLower(strings.TrimSpace(graph.ContentString(odr, "domain")))
				if apex == "" {
					continue
				}
				apexSet[apex] = true
				sibs = append(sibs, nsSibling{apex: apex, edge: oe})
			}
			if len(apexSet) > nsMaxApexes {
				continue // a shared or provider name server
			}

			nsW := graph.WitnessEdge{EdgeID: nse.ID, Label: "name_server", RelationType: nse.Type,
				FromID: nse.FromID, FromType: "DomainRecord", ToID: nse.ToID, ToType: "FQDN"}
			for _, s := range sibs {
				sibW := graph.WitnessEdge{EdgeID: s.edge.ID, Label: "name_server", RelationType: s.edge.Type,
					FromID: s.edge.FromID, FromType: "DomainRecord", ToID: s.edge.ToID, ToType: "FQDN"}
				if !add(s.apex, relatedNSConfidence, "shared name server", nsW, sibW) {
					break nsPivot
				}
			}
		}
	}

	// Official website: domains the organization publishes as its own site
	// (Organization --website--> URL --domain--> FQDN).
	if websites, err := g.Edges(ctx, orgID, "out", "website", time.Time{}); err == nil {
	websiteLoop:
		for _, we := range websites {
			doms, err := g.Edges(ctx, we.ToID, "out", "domain", time.Time{})
			if err != nil {
				continue
			}
			for _, de := range doms {
				fq, err := g.GetAsset(ctx, de.ToID)
				if err != nil {
					continue
				}
				apex := graph.RegisteredDomain(graph.FQDNName(fq))
				webW := graph.WitnessEdge{EdgeID: we.ID, Label: "website", RelationType: we.Type,
					FromID: we.FromID, FromType: "Organization", ToID: we.ToID, ToType: "URL"}
				domW := graph.WitnessEdge{EdgeID: de.ID, Label: "domain", RelationType: de.Type,
					FromID: de.FromID, FromType: "URL", ToID: de.ToID, ToType: "FQDN", To: apex}
				if !add(apex, relatedWebsiteConfidence, "official website", webW, domW) {
					break websiteLoop
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
