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

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
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
	// ownership, even after the default-value catalog skip.
	fpMaxApexes = 25
)

// The per-signal confidences come from the horizontal signal catalog
// (internal/semantics/horizontal_signals.json), so the lens, the runtime
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

	// Never correlate on a privacy proxy or a placeholder organization.
	if name == "" || registrant.IsPrivacyProxyName(name) || semantics.IsPlaceholderOrganization(name) {
		return report, nil
	}

	acc := map[string]*HorizontalDomain{}
	add := func(apex, signalID, signal string, witness ...graph.WitnessEdge) bool {
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
		if !slices.Contains(d.SignalIDs, signalID) {
			d.SignalIDs = append(d.SignalIDs, signalID)
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
			if !add(graph.ContentString(dr, "domain"), SigRegistrantOrg, registrantSig, w, orgWitness(ce)) {
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
				if !add(apex, SigCertSubjectOrg, certSig, certW, orgWitness(ce), sanW) {
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
				if !add(s.apex, SigSharedNameServer, "shared name server", nsW, sibW) {
					break nsPivot
				}
			}
		}
	}

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
	sharedDNSHostPivot(ctx, g, ownApexes, RRTypeNS, SigSharedNameServer, "shared name server", nsMaxApexes,
		isNameServerProvider, add)
	sharedDNSHostPivot(ctx, g, ownApexes, rrTypeMX, SigSharedMX, "shared mail exchanger", mxMaxApexes,
		isMailProvider, add)

	// Mail-policy references: another domain that points its DMARC reporting or
	// SPF sending at one of the organization's own domains.
	policyReferencePivot(ctx, g, ownApexes, "dmarc_reports_to", SigDMARCReportsTo, "shared DMARC reporting",
		dmarcMaxPublishers, isPolicyProvider, add)
	policyReferencePivot(ctx, g, ownApexes, "spf_authorizes", SigSPFAuthorizes, "SPF authorization",
		spfMaxPublishers, isPolicyProvider, add)

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
				if !add(apex, SigOfficialWebsite, "official website", webW, domW) {
					break websiteLoop
				}
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
				w.maxAssets, w.maxReads = LensLimits{}.assets(), LensLimits{}.reads()
				sharedFingerprintPivot(ctx, g, w, org, add)
			}
		}
	}

	report.Domains = make([]HorizontalDomain, 0, len(acc))
	for _, d := range acc {
		// One confidence definition: the noisy-OR of the matched signals'
		// catalog weights, so corroborating signals rank a domain higher.
		d.Confidence, _ = HorizontalScore(d.SignalIDs)
		report.Domains = append(report.Domains, *d)
	}
	sort.Slice(report.Domains, func(i, j int) bool { return report.Domains[i].Domain < report.Domains[j].Domain })
	return report, nil
}

// isMailProvider reports whether host is a mail exchanger of a known mail
// provider (email.json mail_providers), so the shared-mail-exchanger horizontal
// signal can skip it regardless of how many of the provider's customers are in
// the database.
func isMailProvider(host string) bool {
	return mailProviderOf(loadEmailRules(), host) != ""
}

// policyReferencePivot adds related domains that point their published mail
// policy at one of the organization's own apex domains: another domain whose SPF
// record authorizes the org's domain to send (spf_authorizes) or whose DMARC
// record sends its reports to the org's domain (dmarc_reports_to). The engine
// derives both edges from the publishing domain's TXT records and runs them from
// the publishing apex to the referenced domain, so this walks the incoming edges
// of the given label on each of the organization's own apexes. A referenced
// domain pointed at by more than maxPublishers distinct apexes, or one a known
// mail-policy provider operates (isProvider), is shared mail-policy
// infrastructure and is skipped, not scored.
func policyReferencePivot(ctx context.Context, g graph.Graph, ownApexes []string, label,
	signalID, signalLabel string, maxPublishers int, isProvider func(string) bool,
	add func(string, string, string, ...graph.WitnessEdge) bool) {
	for _, apexID := range ownApexes {
		target, err := g.GetAsset(ctx, apexID)
		if err != nil {
			continue
		}
		if isProvider(graph.RegisteredDomain(graph.FQDNName(target))) {
			continue // the organization's own domain is itself a shared endpoint
		}

		edges, err := g.Edges(ctx, apexID, "in", label, time.Time{})
		if err != nil {
			continue
		}
		apexSet := map[string]bool{}
		type publisher struct {
			apex string
			edge graph.Relation
		}
		var pubs []publisher
		for _, pe := range edges {
			pf, err := g.GetAsset(ctx, pe.FromID)
			if err != nil {
				continue
			}
			apex := graph.RegisteredDomain(graph.FQDNName(pf))
			if apex == "" {
				continue
			}
			apexSet[apex] = true
			pubs = append(pubs, publisher{apex: apex, edge: pe})
		}
		if len(apexSet) > maxPublishers {
			continue // a shared mail-policy endpoint referenced by many domains
		}

		for _, p := range pubs {
			w := graph.WitnessEdge{EdgeID: p.edge.ID, Label: label, RelationType: p.edge.Type,
				FromID: p.edge.FromID, FromType: "FQDN", ToID: p.edge.ToID, ToType: "FQDN"}
			if !add(p.apex, signalID, signalLabel, w) {
				return
			}
		}
	}
}

// sharedDNSHostPivot adds related domains that share a DNS host record of the
// given RR type — a name server (NS) or a mail exchanger (MX) — with one of the
// organization's own apex domains. In OAM both are the same shape (an apex FQDN
// pointing to a server FQDN via a dns_record edge), so both are found the same
// way, differing only by RR type. A host a known provider operates (isProvider,
// from a curated provider list) is skipped regardless of database coverage; a
// host shared by more than maxApexes distinct apexes is treated as provider
// infrastructure the list does not yet name and is skipped too. Neither is
// scored. add returning false (the domain cap) stops the pivot.
func sharedDNSHostPivot(ctx context.Context, g graph.Graph, ownApexes []string, rrType int,
	signalID, signalLabel string, maxApexes int, isProvider func(string) bool,
	add func(string, string, string, ...graph.WitnessEdge) bool) {
	seenHost := map[string]bool{}
	for _, apexID := range ownApexes {
		hosts, err := g.Edges(ctx, apexID, "out", "dns_record", time.Time{})
		if err != nil {
			continue
		}
		for _, he := range hosts {
			if relationRRType(he) != rrType || seenHost[he.ToID] {
				continue
			}
			seenHost[he.ToID] = true

			// A name server or mail exchanger a known provider operates serves
			// many unrelated customers, so it is never ownership evidence, even
			// when few of its tenants are in the database yet.
			if host, err := g.GetAsset(ctx, he.ToID); err == nil && isProvider(graph.FQDNName(host)) {
				continue
			}

			others, err := g.Edges(ctx, he.ToID, "in", "dns_record", time.Time{})
			if err != nil {
				continue
			}
			apexSet := map[string]bool{}
			type dnsSibling struct {
				apex string
				edge graph.Relation
			}
			var sibs []dnsSibling
			for _, oe := range others {
				if relationRRType(oe) != rrType {
					continue
				}
				of, err := g.GetAsset(ctx, oe.FromID)
				if err != nil {
					continue
				}
				apex := graph.RegisteredDomain(graph.FQDNName(of))
				if apex == "" {
					continue
				}
				apexSet[apex] = true
				sibs = append(sibs, dnsSibling{apex: apex, edge: oe})
			}
			if len(apexSet) > maxApexes {
				continue // a shared or provider host
			}

			hostW := graph.WitnessEdge{EdgeID: he.ID, Label: "dns_record", RelationType: he.Type,
				FromID: he.FromID, FromType: "FQDN", ToID: he.ToID, ToType: "FQDN"}
			for _, s := range sibs {
				sibW := graph.WitnessEdge{EdgeID: s.edge.ID, Label: "dns_record", RelationType: s.edge.Type,
					FromID: s.edge.FromID, FromType: "FQDN", ToID: s.edge.ToID, ToType: "FQDN"}
				if !add(s.apex, signalID, signalLabel, hostW, sibW) {
					return
				}
			}
		}
	}
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
		if _, strong := HorizontalScore(d.SignalIDs); strong {
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
		return b.String()
	}
	for _, d := range r.Domains {
		fmt.Fprintf(&b, "  %s (confidence %d): %s\n", d.Domain, d.Confidence, strings.Join(d.Signals, ", "))
	}

	return b.String()
}


// fingerprintSignalFor maps a service fingerprint id_type to the horizontal
// signal it supports, for the id_types that are good horizontal evidence. A
// JARM (a TLS-stack fingerprint shared by many unrelated servers) and the page
// title (too generic) are deliberately not horizontal evidence and return
// false.
func fingerprintSignalFor(idType string) (signalID, label string, ok bool) {
	switch idType {
	case fingerprint.AnalyticsID:
		return SigSharedAnalyticsID, "shared analytics identifier", true
	case fingerprint.FaviconMMH3:
		return SigSharedFavicon, "shared favicon", true
	case fingerprint.BodySHA256:
		return SigSharedPageContent, "shared page content", true
	}

	return "", "", false
}

// sharedFingerprintPivot adds related domains whose web service carries the same
// distinctive fingerprint Identifier (analytics identifier, favicon hash or
// page-content hash) as one of the organization's own services. It walks the
// organization's controlled footprint to its services, and for each service's
// fingerprint edge to an Identifier reads the other services carrying that same
// Identifier and takes the registered domain of each one's FQDN host. A default
// or signal-free value (fingerprint_defaults.json) is skipped, and an Identifier
// carried by more distinct apex domains than fpMaxApexes is treated as a shared
// default or CDN value and skipped, not scored. add returning false (the domain
// cap) stops the pivot.
func sharedFingerprintPivot(ctx context.Context, g graph.Graph, w *lensWalker, org graph.Asset,
	add func(string, string, string, ...graph.WitnessEdge) bool) {
	owned, order, err := w.controlledFootprint([]graph.Asset{org})
	if err != nil {
		return
	}
	seenSvc := map[string]bool{}
	for _, id := range order {
		host := owned[id]
		steps, err := w.steps(host)
		if err != nil {
			continue
		}
		for _, hs := range steps {
			if !hs.forward || hs.other.Type != "Service" || seenSvc[hs.other.ID] {
				continue
			}
			seenSvc[hs.other.ID] = true
			svc := hs.other

			svcSteps, err := w.steps(svc)
			if err != nil {
				continue
			}
			for _, fs := range svcSteps {
				if !fs.forward || fs.edge.Label != "fingerprint" {
					continue
				}
				ident := fs.other
				idType := graph.ContentString(ident, "id_type")
				signalID, label, ok := fingerprintSignalFor(idType)
				if !ok {
					continue
				}
				value := graph.ContentString(ident, "id")
				if value == "" || semantics.IsDefaultFingerprint(idType, value) {
					continue
				}
				ownW := graph.WitnessEdge{EdgeID: fs.edge.ID, Label: "fingerprint", RelationType: fs.edge.Type,
					FromID: svc.ID, FromType: "Service", ToID: ident.ID, ToType: "Identifier", To: idType + ":" + value}
				if !fingerprintSiblings(ctx, g, svc.ID, ident.ID, signalID, label, ownW, add) {
					return
				}
			}
		}
	}
}

// fingerprintSiblings reads the other services carrying the Identifier identID
// and adds the registered domain of each one's FQDN host, unless the Identifier
// is over the shared-value cap. ownW is the witness for the organization's own
// service that holds the same Identifier.
func fingerprintSiblings(ctx context.Context, g graph.Graph, ownSvcID, identID, signalID, label string,
	ownW graph.WitnessEdge, add func(string, string, string, ...graph.WitnessEdge) bool) bool {
	carriers, err := g.Edges(ctx, identID, "in", "fingerprint", time.Time{})
	if err != nil {
		return true
	}
	type sibling struct {
		apex     string
		fpEdge   graph.Relation
		hostEdge graph.Relation
	}
	apexSet := map[string]bool{}
	var sibs []sibling
	for _, ce := range carriers {
		if ce.FromID == ownSvcID {
			continue
		}
		hosts, err := g.Edges(ctx, ce.FromID, "in", "port", time.Time{})
		if err != nil {
			continue
		}
		for _, he := range hosts {
			fq, err := g.GetAsset(ctx, he.FromID)
			if err != nil || fq.Type != "FQDN" {
				continue
			}
			apex := graph.RegisteredDomain(graph.FQDNName(fq))
			if apex == "" {
				continue
			}
			apexSet[apex] = true
			sibs = append(sibs, sibling{apex: apex, fpEdge: ce, hostEdge: he})
		}
	}
	if len(apexSet) > fpMaxApexes {
		return true // a shared default or CDN value, not ownership evidence
	}
	for _, sb := range sibs {
		sibW := graph.WitnessEdge{EdgeID: sb.fpEdge.ID, Label: "fingerprint", RelationType: sb.fpEdge.Type,
			FromID: sb.fpEdge.FromID, FromType: "Service", ToID: sb.fpEdge.ToID, ToType: "Identifier"}
		hostW := graph.WitnessEdge{EdgeID: sb.hostEdge.ID, Label: "port", RelationType: sb.hostEdge.Type,
			FromID: sb.hostEdge.FromID, FromType: "FQDN", ToID: sb.hostEdge.ToID, ToType: "Service", To: sb.apex}
		if !add(sb.apex, signalID, label, ownW, sibW, hostW) {
			return false
		}
	}

	return true
}
