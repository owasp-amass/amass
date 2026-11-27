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
//     of the organization's own domains (from the registration record and from
//     resolved DNS), skipping a shared/provider name server.
//   - shared mail exchanger: another domain whose mail is handled by the same
//     MX host as one of the organization's own domains — the same shape as a
//     name server in OAM — skipping a shared mail provider.
//   - official website: a domain the organization publishes as its own website
//     (e.g. recorded by the Wikidata official-website collector).
//
// A WHOIS privacy proxy or a placeholder organization is shared by many
// unrelated domains, so such a subject is never correlated on. A certificate or
// name server shared by more than a cap of distinct apexes is provider/CDN
// infrastructure, not shared ownership, and is skipped.

const (
	// certMaxApexes / nsMaxApexes skip a certificate or name server covering
	// more distinct apex domains than this: shared or CDN/provider
	// infrastructure spanning many tenants is not evidence of shared ownership
	// (principle 8). The database's hub limit for the certificate's listing
	// label, or for name servers, replaces each when the database can say
	// (graph.HubLimit).
	certMaxApexes = 25
	nsMaxApexes   = 25
	// mxMaxApexes skips a mail exchanger serving more distinct apex domains than
	// this: a shared mail provider (Google Workspace, Microsoft 365, …), not
	// evidence of shared ownership.
	mxMaxApexes = 25
	// dmarcMaxPublishers and spfMaxPublishers skip one of the organization's
	// domains referenced by more distinct apexes than this in their DMARC
	// reporting or SPF records: a shared mail-policy endpoint (a DMARC processor
	// or a provider's SPF macro), not evidence of shared ownership.
	dmarcMaxPublishers = 25
	spfMaxPublishers   = 25
	// fpMaxApexes skips a service fingerprint Identifier carried by more
	// distinct apex domains than this: a shared default or CDN value (a
	// framework favicon, a parked-page body), not evidence of shared
	// ownership, even after the default-value catalog skip. The database's
	// hub limit for fingerprints replaces it when the database can say.
	fpMaxApexes = 25
)

// The per-signal confidences come from the horizontal signal catalog
// (internal/semantics/signals.json, related-domain uses), so the lens, the runtime
// scope-expansion decision and the classifier share one source of truth
// (principle 8). Each is the signal's catalog weight times 100.
var (
	relatedRegistrantConfidence = HorizontalConfidence(SigRegistrantOrg)
	relatedCertConfidence       = HorizontalConfidence(SigCertSubjectOrg)
	relatedNSConfidence         = HorizontalConfidence(SigSharedNameServer)
	relatedMXConfidence         = HorizontalConfidence(SigSharedMX)
	relatedDMARCConfidence      = HorizontalConfidence(SigDMARCReportsTo)
	relatedSPFConfidence        = HorizontalConfidence(SigSPFAuthorizes)
	relatedWebsiteConfidence    = HorizontalConfidence(SigOfficialWebsite)
)

// HorizontalDomain is a registered (apex) domain a horizontal signal ties to
// the subject organization, with the evidence and confidence behind it.
// Confidence is the noisy-OR combination of the matched signals' catalog
// weights (HorizontalScore), so a domain found by several signals ranks above
// one found by a single signal. SignalIDs are the catalog ids of those signals,
// for the scorer and the classifier; Signals are the human-readable reasons.
type HorizontalDomain struct {
	Domain     string              `json:"domain"`
	Confidence int                 `json:"confidence"`
	Signals    []string            `json:"signals"`
	SignalIDs  []string            `json:"signal_ids,omitempty"`
	Witness    []graph.WitnessEdge `json:"witness,omitempty"`
	// ContributedSignals are the strong signals among SignalIDs that rest
	// on what assistants contributed; they score as supporting
	// (contributionJudge).
	ContributedSignals []string `json:"contributed_signals,omitempty"`
}

// RelatedDomainsReport is the result of a horizontal related-domain search for
// one organization.
type RelatedDomainsReport struct {
	OrgID     string             `json:"org_id"`
	Org       string             `json:"org"`
	Domains   []HorizontalDomain `json:"domains"`
	Truncated string             `json:"truncated,omitempty"`
	// HubSkips are the shared values the signals passed over as provider
	// infrastructure, with the limit that stopped each.
	HubSkips []HubSkip `json:"hub_skips,omitempty"`
}

// nsSibling is a domain record sharing a name server with the subject's own.
type nsSibling struct {
	apex string
	edge graph.Relation
}

// FindRelatedDomains finds the registered domains the horizontal signals tie to
// an organization, read-only. It returns nothing for a privacy proxy or a
// placeholder organization, which many unrelated domains share (principle 8).
func FindRelatedDomains(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, orgID string) (RelatedDomainsReport, error) {
	org, err := g.GetAsset(ctx, orgID)
	if err != nil {
		return RelatedDomainsReport{}, err
	}
	if org.Type != "Organization" {
		return RelatedDomainsReport{}, fmt.Errorf("%s is not an Organization", orgID)
	}

	name := graph.ContentString(org, "name")
	report := RelatedDomainsReport{OrgID: orgID, Org: name}
	skips := &hubSkips{}

	// Never correlate on a privacy proxy or a placeholder organization.
	if name == "" || registrant.IsPrivacyProxyName(name) || semantics.IsPlaceholderOrganization(name) {
		return report, nil
	}

	acc := map[string]*HorizontalDomain{}
	witnesses := signalWitnesses{}
	add := func(apex, signalID, signal string, witness ...graph.WitnessEdge) {
		apex = strings.ToLower(strings.TrimSpace(apex))
		if apex == "" {
			return
		}
		d, ok := acc[apex]
		if !ok {
			d = &HorizontalDomain{Domain: apex}
			acc[apex] = d
		}
		if !slices.Contains(d.SignalIDs, signalID) {
			d.SignalIDs = append(d.SignalIDs, signalID)
		}
		if !slices.Contains(d.Signals, signal) {
			d.Signals = append(d.Signals, signal)
		}
		d.Witness = append(d.Witness, witness...)
		witnesses.add(apex, signalID, witness)
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

	certHub := derivedHub(ctx, g, "san_dns_name", "out", certMaxApexes, skips)
	nsHub := derivedHub(ctx, g, "name_server", "in", nsMaxApexes, skips)
	for _, ce := range contacts {
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
			add(graph.ContentString(dr, "domain"), SigRegistrantOrg, registrantSig, w, orgWitness(ce))
		}

		// TLSCertificate --subject_contact--> ContactRecord.
		certs, err := g.Edges(ctx, ce.FromID, "in", "subject_contact", time.Time{})
		if err != nil {
			return report, err
		}
		for _, cte := range certs {
			apexes := certApexes(ctx, g, cte.FromID)
			if len(apexes) == 0 {
				continue
			}
			if certHub.exceeded(len(apexes), false) {
				// a shared or CDN certificate
				certHub.record(assetName(ctx, g, cte.FromID), len(apexes), false)
				continue
			}
			certW := graph.WitnessEdge{EdgeID: cte.ID, Label: "subject_contact", RelationType: cte.Type,
				FromID: cte.FromID, FromType: "TLSCertificate", ToID: cte.ToID, ToType: "ContactRecord"}
			for _, apex := range sortedRelationKeys(apexes) {
				fq := apexes[apex]
				sanW := graph.WitnessEdge{EdgeID: fq.ID, Label: fq.Label, RelationType: fq.Type,
					FromID: fq.FromID, FromType: "TLSCertificate", ToID: fq.ToID, ToType: "FQDN", To: apex}
				add(apex, SigCertSubjectOrg, certSig, certW, orgWitness(ce), sanW)
			}
		}
	}

	// ownDomains are the organization's registered domains: a name server or
	// mail exchanger inside them is the organization's own, the strong tier
	// of the shared-host signals.
	var ownDomains []string
	for _, drID := range ownDRs {
		if dr, err := g.GetAsset(ctx, drID); err == nil {
			if d := strings.ToLower(strings.TrimSpace(graph.ContentString(dr, "domain"))); d != "" {
				ownDomains = append(ownDomains, d)
			}
		}
	}

	// Shared name server: domains served by the same non-provider name server
	// as one of the organization's own domains.
	seenNS := map[string]bool{}
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

			// A name server a known managed-DNS provider operates serves many
			// unrelated customers, so it is never ownership evidence, even when
			// few of its tenants are in the database yet (the same guard as the
			// DNS-record pivot below); a full delegation set is weighed by
			// delegationSetPivot instead.
			host, err := g.GetAsset(ctx, nse.ToID)
			if err == nil && isNameServerProvider(graph.FQDNName(host)) {
				continue
			}
			nsSig, nsLabel := SigSharedNameServer, "shared name server"
			if err == nil && withinAny(graph.FQDNName(host), ownDomains) {
				nsSig, nsLabel = SigNameServerOwn, "name server run by the organization: "+graph.FQDNName(host)
			}

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
			if nsHub.exceeded(len(apexSet), false) {
				// a shared or provider name server
				nsHub.record(assetName(ctx, g, nse.ToID), len(apexSet), false)
				continue
			}

			nsW := graph.WitnessEdge{EdgeID: nse.ID, Label: "name_server", RelationType: nse.Type,
				FromID: nse.FromID, FromType: "DomainRecord", ToID: nse.ToID, ToType: "FQDN"}
			for _, s := range sibs {
				sibW := graph.WitnessEdge{EdgeID: s.edge.ID, Label: "name_server", RelationType: s.edge.Type,
					FromID: s.edge.FromID, FromType: "DomainRecord", ToID: s.edge.ToID, ToType: "FQDN"}
				add(s.apex, nsSig, nsLabel, nsW, sibW)
			}
		}
	}

	// Same DNS provider delegation set: a domain delegated to exactly the
	// same full set of a unique_set provider's name servers (a Route 53
	// delegation set). Those servers serve thousands of zones each, so the
	// per-server pivot above skips them; only the whole set identifies an
	// account.
	delegationSetPivot(ctx, g, ownDRs, nsHub, add)

	// Shared DNS host records resolved via DNS: an apex FQDN's dns_record NS and
	// MX edges, extracted the same way (a name server and a mail exchanger are
	// both an apex pointing to a server FQDN, differing only by RR type). The NS
	// pivot complements the registration name_server pivot above — DNS records
	// exist for any resolved domain, so a sibling whose registration was never
	// fetched is still found — and the MX pivot adds the mail-exchanger signal.
	var ownApexes []string
	seenApex := map[string]bool{}
	for _, drID := range ownDRs {
		regs, err := g.Edges(ctx, drID, "in", "registration", time.Time{})
		if err != nil {
			continue
		}
		for _, re := range regs {
			if !seenApex[re.FromID] {
				seenApex[re.FromID] = true
				ownApexes = append(ownApexes, re.FromID)
			}
		}
	}
	allowedOriginPivot(ctx, g, ownApexes, add)
	bountyScopePivot(ctx, g, name, ownApexes, add)
	packagePivot(ctx, g, ownApexes, ownDomains, add)
	adsSellerPivot(ctx, g, ownApexes, ownDomains, skips, add)
	soaMailboxPivot(ctx, g, ownApexes, derivedHub(ctx, g, "soa_rname", "in", soaMaxApexes, skips), add)
	sharedDNSHostPivot(ctx, g, ownApexes, RRTypeNS, SigSharedNameServer, "shared name server", nsHub,
		isNameServerProvider, ownHostTier{signalID: SigNameServerOwn, label: "name server run by the organization",
			domains: ownDomains}, add)
	sharedDNSHostPivot(ctx, g, ownApexes, rrTypeMX, SigSharedMX, "shared mail exchanger",
		fixedHub("mail exchanger", mxMaxApexes, skips),
		isMailProvider, ownHostTier{signalID: SigMXOwn, label: "mail exchanger run by the organization",
			domains: ownDomains}, add)

	// Mail-policy references: another domain that points its DMARC reporting or
	// SPF sending at one of the organization's own domains.
	policyReferencePivot(ctx, g, ownApexes, "dmarc_reports_to", SigDMARCReportsTo, "shared DMARC reporting",
		fixedHub("DMARC reporting domain", dmarcMaxPublishers, skips), isPolicyProvider, nil, add)
	policyReferencePivot(ctx, g, ownApexes, "spf_authorizes", SigSPFAuthorizes, "SPF authorization",
		fixedHub("SPF domain", spfMaxPublishers, skips), isPolicyProvider, ownDomains, add)

	// Official website: domains the organization publishes as its own site
	// (Organization --website--> URL --domain--> FQDN).
	if websites, err := g.Edges(ctx, orgID, "out", "website", time.Time{}); err == nil {
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
				add(apex, SigOfficialWebsite, "official website", webW, domW)
			}
		}
	}

	// Shared service fingerprints: another apex whose web service carries the
	// same distinctive fingerprint Identifier (analytics id, favicon or page
	// content) as one of the organization's own services. This reaches the
	// service layer, so it needs the relationship schema; without it (a caller
	// that passes none) the rest of the lens still runs.
	if schema != nil {
		if meaning := graph.MeaningsOf(schema); meaning != nil {
			if bounded, ok := g.(graph.BoundedGraph); ok {
				fpReport := &ThirdPartyReport{Root: org, FootprintTypes: map[string]int{}}
				w := newLensWalker(ctx, g, bounded, meaning, schema.Relations(), org, fpReport)
				sharedFingerprintPivot(ctx, g, w, org, skips, add)
			}
		}
	}

	report.Domains = make([]HorizontalDomain, 0, len(acc))
	judge := newContributionJudge(ctx, g)
	for _, d := range acc {
		d.ContributedSignals = witnesses.contributed(judge, d.Domain, d.SignalIDs, LookupHorizontalSignal)
		// One confidence definition: the noisy-OR of the matched signals'
		// catalog weights, so corroborating signals rank a domain higher.
		d.Confidence, _ = HorizontalScore(d.SignalIDs, d.ContributedSignals)
		report.Domains = append(report.Domains, *d)
	}
	sort.Slice(report.Domains, func(i, j int) bool { return report.Domains[i].Domain < report.Domains[j].Domain })
	report.HubSkips = skips.sorted()
	return report, nil
}

// HorizontalExpansion partitions a related-domains report into the candidates a
// strong signal justifies adding to scope during enumeration (expand) and those
// that are corroboration only and need review (needsReview). It is the decision
// the runtime scope-expansion pass consumes: a candidate expands only when its
// signals include a strong one (HorizontalScore), never on a lone weak signal
// such as a shared name server. The classifier adjudicates the needs-review
// set in a later increment.
func HorizontalExpansion(r RelatedDomainsReport) (expand, needsReview []HorizontalDomain) {
	for _, d := range r.Domains {
		if _, strong := HorizontalScore(d.SignalIDs, d.ContributedSignals); strong {
			expand = append(expand, d)
		} else {
			needsReview = append(needsReview, d)
		}
	}

	return expand, needsReview
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
	}
	for _, d := range r.Domains {
		fmt.Fprintf(&b, "  %s (confidence %d): %s\n", d.Domain, d.Confidence, strings.Join(d.Signals, ", "))
	}
	if text := hubSkipText(r.HubSkips); text != "" {
		b.WriteString(strings.TrimSpace(text) + "\n")
	}

	return b.String()
}
