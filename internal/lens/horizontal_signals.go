// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
)

// The signal catalog's related-domain uses define the evidence that ties
// another registered (apex) domain to a target organization. The
// related-domains lens, the runtime scope-expansion decision and the
// classifier read them, so all three share one source of truth
// (ai-design-principles.md, principle 8).

// Horizontal signal IDs, as used in code and in signals.json.
const (
	SigRegistrantOrg    = "shared-registrant-org"
	SigCertSubjectOrg   = "cert-subject-org"
	SigSharedNameServer = "shared-name-server"
	// SigDNSDelegationSet is another apex delegated to the same full name
	// server set of a provider that gives each account or zone its own set.
	SigDNSDelegationSet = "dns-provider-delegation-set"
	// SigAllowedOrigin is another apex an organization's web service lets
	// call or embed it (CORS, CSP frame-ancestors).
	SigAllowedOrigin = "allowed-origin"
	// SigBountyScope is another apex a bug-bounty program tied to the
	// organization lists in its scope.
	SigBountyScope = "bug-bounty-scope"
	// SigSOAMailboxOwn is another apex whose SOA names an administrator
	// mailbox at one of the organization's domains; SigSharedSOAMailbox one
	// sharing an outside mailbox with one of its zones.
	SigSOAMailboxOwn    = "soa-mailbox-own-domain"
	SigSharedSOAMailbox = "shared-soa-mailbox"
	// SigPackageOrganization is another apex a package in the organization's
	// verified Maven group names as its publisher's site; SigPackageWebsite
	// one any of the organization's packages names otherwise.
	SigPackageOrganization = "package-publisher-site"
	SigPackageWebsite      = "package-website"
	// SigCodeHostWebsite is another apex a code-host organization tied to
	// one of the organization's domains names as its or a repository's
	// website.
	SigCodeHostWebsite = "code-host-website"
	// SigSharedAdsSeller is another apex whose ads.txt lists one of the
	// organization's DIRECT ad seller accounts; SigAdsSellerDomain the domain
	// an ad system's sellers.json gives for such an account.
	SigSharedAdsSeller = "shared-ads-seller"
	SigAdsSellerDomain = "ads-seller-domain"
	// SigAdsOwnerDomain is the owner's business domain the organization's
	// ads.txt names (OWNERDOMAIN).
	SigAdsOwnerDomain = "ads-owner-domain"
	// SigAdsOwnedBy is another apex whose ads.txt names one of the
	// organization's domains as its owner's.
	SigAdsOwnedBy = "ads-owned-by"
	// The strong tiers of the shared-host and SPF signals: a name server or
	// mail exchanger inside the organization's own domains, and a domain
	// that sends all its mail through the organization.
	SigNameServerOwn   = "name-server-own-domain"
	SigMXOwn           = "mx-own-domain"
	SigSPFExclusive    = "spf-authorizes-exclusive"
	SigSharedMX        = "shared-mx"
	SigDMARCReportsTo  = "dmarc-reports-to"
	SigSPFAuthorizes   = "spf-authorizes"
	SigOfficialWebsite = "official-website"
	// Shared service fingerprints: another apex whose service carries the
	// same distinctive fingerprint Identifier as one of the org's services.
	SigSharedAnalyticsID = "shared-analytics-id"
	SigSharedFavicon     = "shared-favicon"
	SigSharedPageContent = "shared-page-content"
	// Identity system: another apex on the same identity tenant (an Entra
	// tenant or Okta organization), one Microsoft lists as sharing the
	// organization's tenant, and one signing in at a federation server that
	// shares the organization's token-signing certificate.
	SigSharedIdentityTenant = "shared-identity-tenant"
	SigFederatedSibling     = "federated-sibling"
	SigSharedSigningCert    = "shared-signing-certificate"
)

// Horizontal signal matchers: how each signal is found in the graph.
const (
	matchHorRegistrantOrg = "shared_registrant_org"
	matchHorCertOrg       = "certificate_subject_org"
	matchHorNameServer    = "shared_name_server"
	matchHorMX            = "shared_mx"
	matchHorDMARC         = "dmarc_reports_to"
	matchHorSPF           = "spf_authorizes"
	matchHorWebsite       = "official_website"
	matchHorFingerprint   = "shared_service_fingerprint"
	matchHorDelegationSet = "provider_delegation_set"
	matchHorAllowedOrigin = "allowed_origin"
	matchHorBountyScope   = "bounty_program_scope"
	matchHorSOAOwn        = "soa_mailbox_own_domain"
	matchHorSOAShared     = "soa_mailbox"
	matchHorNSOwn         = "name_server_own_domain"
	matchHorMXOwn         = "mx_own_domain"
	matchHorSPFExclusive  = "spf_authorizes_exclusive"
	matchHorPackageOrg    = "package_publisher_site"
	matchHorPackageSite   = "package_website"
	matchHorCodeHostSite  = "code_host_website"
	matchHorAdsSeller     = "shared_ads_seller"
	matchHorAdsSellerDom  = "ads_seller_domain"
	matchHorAdsOwnerDom   = "ads_owner_domain"
	matchHorAdsOwnedBy    = "ads_owned_by"
	matchHorTenant        = "shared_identity_tenant"
	matchHorFederated     = "federated_sibling"
	matchHorSigningCert   = "shared_signing_certificate"
)

var horizontalMatchers = map[string]bool{matchHorRegistrantOrg: true, matchHorCertOrg: true,
	matchHorNameServer: true, matchHorMX: true, matchHorDMARC: true, matchHorSPF: true, matchHorWebsite: true,
	matchHorFingerprint: true, matchHorDelegationSet: true, matchHorAllowedOrigin: true,
	matchHorBountyScope: true, matchHorSOAOwn: true, matchHorSOAShared: true,
	matchHorNSOwn: true, matchHorMXOwn: true, matchHorSPFExclusive: true, matchHorPackageOrg: true,
	matchHorPackageSite: true, matchHorAdsSeller: true, matchHorAdsSellerDom: true,
	matchHorAdsOwnerDom: true, matchHorAdsOwnedBy: true, matchHorTenant: true, matchHorFederated: true,
	matchHorSigningCert: true, matchHorCodeHostSite: true}

var loadHorizontalCatalog = sync.OnceValues(func() (signalCatalog, error) {
	c, err := signalView(UseRelatedDomain)
	if err != nil {
		return c, err
	}

	if err := validateHorizontalSignals(c.Signals); err != nil {
		return c, fmt.Errorf("signals.json %s: %w", UseRelatedDomain, err)
	}
	return c, nil
})

func validateHorizontalSignals(signals []OwnershipSignal) error {
	seen := map[string]bool{}
	for _, s := range signals {
		switch {
		case s.ID == "" || seen[s.ID]:
			return fmt.Errorf("signal %q: missing or repeated id", s.ID)
		case s.Title == "" || s.Kind == "" || s.Finds == "" || s.Rationale == "":
			return fmt.Errorf("signal %s: title, kind, finds and rationale are required", s.ID)
		case s.Strength != StrengthStrong && s.Strength != StrengthSupporting:
			return fmt.Errorf("signal %s: strength must be strong or supporting", s.ID)
		case s.Weight <= 0 || s.Weight > signalCatalogMaxWeight:
			return fmt.Errorf("signal %s: weight must be in (0, 1]", s.ID)
		case !horizontalMatchers[s.Matcher]:
			return fmt.Errorf("signal %s: unknown matcher %q", s.ID, s.Matcher)
		case len(s.Guards) == 0 || len(s.CounterIndications) == 0:
			return fmt.Errorf("signal %s: guards and counter_indications are required", s.ID)
		}
		if err := validHub(s, horizontalHubMatchers[s.Matcher]); err != nil {
			return err
		}

		seen[s.ID] = true
	}

	return nil
}

// HorizontalSignals returns the horizontal domain-correlation signal catalog.
func HorizontalSignals() []OwnershipSignal {
	c, err := loadHorizontalCatalog()
	if err != nil {
		panic(err)
	}

	return c.Signals
}

// horizontalHubMatchers are the related-domain matchers that pivot on a
// shared value, so their signals need a hub limit.
var horizontalHubMatchers = map[string]bool{matchHorCertOrg: true, matchHorNameServer: true, matchHorMX: true,
	matchHorDMARC: true, matchHorSPF: true, matchHorFingerprint: true, matchHorSOAShared: true,
	matchHorAdsSeller: true, matchHorTenant: true, matchHorSigningCert: true}

// relatedHub is the hub limit of the related-domain signal with id.
func relatedHub(id string) SignalHub {
	if s, ok := LookupHorizontalSignal(id); ok && s.Params.Hub != nil {
		return *s.Params.Hub
	}
	return SignalHub{Limit: GapMaxShared}
}

// LookupHorizontalSignal returns the catalog entry for id.
func LookupHorizontalSignal(id string) (OwnershipSignal, bool) {
	for _, s := range HorizontalSignals() {
		if s.ID == id {
			return s, true
		}
	}

	return OwnershipSignal{}, false
}

// HorizontalConfidence is the 0-100 confidence the related-domains lens records
// for a domain supported by the signal id: the signal's catalog weight times
// 100. An unknown id yields 0, which a lens or scorer test catches.
func HorizontalConfidence(id string) int {
	s, ok := LookupHorizontalSignal(id)
	if !ok {
		return 0
	}

	return int(math.Round(s.Weight * 100))
}

// HorizontalScore combines the catalog weights of the given signal ids into one
// 0-100 confidence with a noisy-OR, so independent signals corroborate — two
// signals score higher than either alone — without ever exceeding 100, and
// reports whether the set includes a strong signal. The caller excludes
// provider- and proxy-owned shared values before scoring. A set with no strong
// signal is corroboration only: the runtime scope-expansion decision treats it
// as needing review rather than an automatic widen, so a lone weak signal (a
// shared name server by itself) never grows scope on its own (principle 8 and
// the horizontal-domain-correlation decided design). A strong signal in
// contributed, which rests on contributions, counts as supporting.
func HorizontalScore(ids, contributed []string) (confidence int, strong bool) {
	return signalScore(ids, contributed, LookupHorizontalSignal)
}

// signalScore is the shared noisy-OR scorer used by the horizontal and
// infrastructure catalogs: it combines the weights of the distinct, known
// signals in ids and reports whether any is strong. The caller supplies the
// catalog lookup.
func signalScore(ids, contributed []string, lookup func(string) (OwnershipSignal, bool)) (confidence int,
	strong bool) {
	seen := map[string]bool{}
	missed := 1.0
	for _, id := range ids {
		if seen[id] {
			continue
		}
		s, ok := lookup(id)
		if !ok {
			continue
		}
		seen[id] = true
		if s.Strength == StrengthStrong && !slices.Contains(contributed, id) {
			strong = true
		}
		missed *= 1 - s.Weight
	}
	if len(seen) == 0 {
		return 0, false
	}

	return int(math.Round((1 - missed) * 100)), strong
}

// HorizontalSignalsMarkdown renders the horizontal catalog as the user
// documentation in docs/ai/HORIZONTALS.md.
func HorizontalSignalsMarkdown() string {
	c, err := loadHorizontalCatalog()
	if err != nil {
		panic(err)
	}

	var b strings.Builder
	b.WriteString("# Horizontal domain correlation\n\n")
	b.WriteString("<!-- Generated from internal/semantics/signals.json (related-domain uses) by `amass review " +
		"horizontal-signals -format markdown`. Edit that file, not this one. -->\n\n")
	b.WriteString("Horizontal correlation associates more registered (apex) domains with a target organization, so an " +
		"enumeration's scope can be made more complete. Each kind of evidence is a signal, listed here with why it " +
		"counts, what stops it from misfiring, and when it can still mislead. The same text is shown by `amass review " +
		"horizontal-signals`.\n\n")
	b.WriteString("## How signals decide\n\n")
	b.WriteString("- The `related-domains` lens surfaces a candidate apex domain for every signal that supports it, " +
		"recording the strongest signal's confidence (its weight times 100) and the evidence; it never changes scope " +
		"itself.\n")
	b.WriteString("- During enumeration the scope-expansion decision scores a candidate over its strong signals, with " +
		"provider- and proxy-owned shared values excluded and a name match never sufficient on its own, and is " +
		"reevaluated as new evidence arrives. The classifier reads the same catalog.\n")
	b.WriteString("- A **strong** signal is direct ownership evidence (a shared registrant or certificate-subject " +
		"organization, an official website); a **supporting** signal (a shared name server) corroborates but can be " +
		"shared infrastructure.\n\n")
	b.WriteString("| Signal | Strength | Kind | Weight |\n| --- | --- | --- | --- |\n")
	for _, s := range c.Signals {
		fmt.Fprintf(&b, "| [%s](#%s) | %s | %s | %.2f |\n", s.Title, s.ID, s.Strength, s.Kind, s.Weight)
	}
	for _, s := range c.Signals {
		fmt.Fprintf(&b, "\n<a id=\"%s\"></a>\n## %s\n\n", s.ID, s.Title)
		fmt.Fprintf(&b, "`%s`: %s %s signal, weight %.2f (confidence %d).\n\n", s.ID, s.Strength, s.Kind, s.Weight,
			HorizontalConfidence(s.ID))
		fmt.Fprintf(&b, "**Finds:** %s\n\n**Why it counts:** %s\n", s.Finds, s.Rationale)
		writeList(&b, "Guards", s.Guards)
		writeList(&b, "Can still mislead when", s.CounterIndications)
		writeHub(&b, s.Params.Hub)
		if signalUses(s.ID)[UseOwnedAsset] {
			fmt.Fprintf(&b, "\nThe same evidence is also ownership evidence: see [%s](SIGNALS.md#%s).\n",
				s.Title, s.ID)
		}
	}

	return b.String()
}

// HorizontalSignalsText renders the horizontal catalog for a terminal.
func HorizontalSignalsText() string {
	var b strings.Builder
	for i, s := range HorizontalSignals() {
		if i > 0 {
			b.WriteString("\n")
		}

		fmt.Fprintf(&b, "%s (%s): %s %s signal, weight %.2f (confidence %d)\n", s.Title, s.ID, s.Strength, s.Kind,
			s.Weight, HorizontalConfidence(s.ID))
		fmt.Fprintf(&b, "  Finds: %s\n  Why it counts: %s\n", s.Finds, s.Rationale)
		for _, g := range s.Guards {
			fmt.Fprintf(&b, "  Guard: %s\n", g)
		}
		for _, c := range s.CounterIndications {
			fmt.Fprintf(&b, "  Can mislead: %s\n", c)
		}
	}

	return b.String()
}
