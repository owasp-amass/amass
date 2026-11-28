// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Advertising seller accounts (engine plugin adstxt): a domain's ads.txt URL
// carries a fingerprint Identifier (ads_seller, "<ad system>:<account>") for
// each DIRECT account it lists. An account the ad system's sellers.json lists
// is a seller Account (Account --id--> Identifier) carrying its seller type,
// with the business domain listed for it as the Account's ContactRecord
// (Account --contact--> ContactRecord --fqdn--> FQDN).
const (
	adsPropSellerType = "seller_type"
	adsIntermediary   = "INTERMEDIARY"
	adsSellerAccount  = "ads_seller"
)

// adsSellerPivot finds the other registered domains tied to the
// organization's own advertising seller accounts: a domain whose ads.txt
// lists the same DIRECT account (strong, as a shared analytics property is,
// within the same shared-value cap), the domain the ad system's sellers.json
// gives for the account when it is another domain, the owner domain the
// organization's own ads.txt names, and another site whose ads.txt names the
// organization's domain as its owner's (all supporting).
// An account the ad system lists as an INTERMEDIARY belongs to a sales house,
// not the publisher, and gives neither.
func adsSellerPivot(ctx context.Context, g graph.Graph, ownApexes, ownDomains []string, skips *hubSkips,
	add func(string, string, string, ...graph.WitnessEdge)) {
	seen := map[string]bool{}
	for _, apexID := range ownApexes {
		apex, err := g.GetAsset(ctx, apexID)
		if err != nil || graph.FQDNName(apex) == "" {
			continue
		}
		adsOwnedBy(ctx, g, apexID, ownDomains, add)
		for _, file := range hostFiles(ctx, g, apex, semantics.AdsTxtCatalog().Files) {
			adsOwnerDomain(ctx, g, file, ownDomains, add)
			adsAccounts(ctx, g, file, ownDomains, seen, skips, add)
		}
	}
}

// adsOwnerDomain adds the owner's business domain an ads.txt file names
// (URL --contact--> ContactRecord --fqdn--> FQDN, from OWNERDOMAIN), when it is
// another domain.
func adsOwnerDomain(ctx context.Context, g graph.Graph, file graph.Asset, ownDomains []string,
	add func(string, string, string, ...graph.WitnessEdge)) {
	contacts, err := g.Edges(ctx, file.ID, "out", "contact", time.Time{})
	if err != nil {
		return
	}
	for _, ce := range contacts {
		owners, err := g.Edges(ctx, ce.ToID, "out", "fqdn", time.Time{})
		if err != nil {
			continue
		}
		contactW := graph.WitnessEdge{EdgeID: ce.ID, Label: "contact", RelationType: ce.Type, FromID: file.ID,
			FromType: "URL", ToID: ce.ToID, ToType: "ContactRecord"}
		for _, oe := range owners {
			owner, err := g.GetAsset(ctx, oe.ToID)
			if err != nil {
				continue
			}
			host := graph.FQDNName(owner)
			dom := graph.RegisteredDomain(host)
			if dom == "" || withinAny(host, ownDomains) {
				continue
			}
			ownerW := graph.WitnessEdge{EdgeID: oe.ID, Label: "fqdn", RelationType: oe.Type, FromID: ce.ToID,
				FromType: "ContactRecord", ToID: oe.ToID, ToType: "FQDN", To: host}
			add(dom, SigAdsOwnerDomain, "the owner domain the organization's ads.txt names", contactW,
				ownerW)
		}
	}
}

// adsOwnedBy adds the sites whose ads.txt names one of the organization's
// domains as the owner's (FQDN <--fqdn-- ContactRecord <--contact-- URL
// --domain--> the site).
func adsOwnedBy(ctx context.Context, g graph.Graph, apexID string, ownDomains []string,
	add func(string, string, string, ...graph.WitnessEdge)) {
	named, err := g.Edges(ctx, apexID, "in", "fqdn", time.Time{})
	if err != nil {
		return
	}
	files := semantics.AdsTxtCatalog().Files
	for _, ne := range named {
		filesIn, err := g.Edges(ctx, ne.FromID, "in", "contact", time.Time{})
		if err != nil {
			continue
		}
		ownerW := graph.WitnessEdge{EdgeID: ne.ID, Label: "fqdn", RelationType: ne.Type, FromID: ne.FromID,
			FromType: "ContactRecord", ToID: apexID, ToType: "FQDN"}
		for _, fe := range filesIn {
			file, err := g.GetAsset(ctx, fe.FromID)
			if err != nil || file.Type != "URL" || !slices.Contains(files, graph.ContentString(file, "path")) {
				continue
			}
			for _, h := range carrierHosts(ctx, g, file.ID) {
				host := graph.FQDNName(h.host)
				dom := graph.RegisteredDomain(host)
				if dom == "" || withinAny(host, ownDomains) {
					continue
				}
				contactW := graph.WitnessEdge{EdgeID: fe.ID, Label: "contact", RelationType: fe.Type,
					FromID: file.ID, FromType: "URL", ToID: ne.FromID, ToType: "ContactRecord"}
				add(dom, SigAdsOwnedBy, "its ads.txt names the organization's domain as the owner's",
					ownerW, contactW, h.witness(dom))
			}
		}
	}
}

// adsAccounts adds the domains tied to the DIRECT accounts one ads.txt file
// lists.
func adsAccounts(ctx context.Context, g graph.Graph, file graph.Asset, ownDomains []string, seen map[string]bool,
	skips *hubSkips, add func(string, string, string, ...graph.WitnessEdge)) {
	fps, err := g.Edges(ctx, file.ID, "out", "fingerprint", time.Time{})
	if err != nil {
		return
	}
	for _, fe := range fps {
		ident, err := g.GetAsset(ctx, fe.ToID)
		if err != nil || graph.ContentString(ident, "id_type") != fingerprint.AdsSeller || seen[ident.ID] {
			continue
		}
		seen[ident.ID] = true
		value := graph.ContentString(ident, "id")

		sellerType, sellerDomain, sellerW := adsSeller(ctx, g, ident.ID)
		if sellerType == adsIntermediary {
			continue
		}

		ownW := graph.WitnessEdge{EdgeID: fe.ID, Label: "fingerprint", RelationType: fe.Type, FromID: file.ID,
			FromType: "URL", ToID: ident.ID, ToType: "Identifier", To: fingerprint.AdsSeller + ":" + value}
		fingerprintSiblings(ctx, g, file.ID, ident.ID, SigSharedAdsSeller,
			"same DIRECT ad seller account "+value, ownW, signalHub(ctx, g, relatedHub(SigSharedAdsSeller),
				fingerprintSource(fingerprint.AdsSeller), "fingerprint "+fingerprint.AdsSeller, skips), add)

		system, _, _ := strings.Cut(value, ":")
		host := webHost(sellerDomain)
		dom := graph.RegisteredDomain(host)
		if dom == "" || withinAny(host, ownDomains) || dom == graph.RegisteredDomain(system) {
			continue
		}
		add(dom, SigAdsSellerDomain, "the domain "+system+" lists for ad seller account "+value,
			append([]graph.WitnessEdge{ownW}, sellerW...)...)
	}
}

// adsSeller returns the seller type and business domain the ad system's
// sellers.json lists for an ads_seller Identifier, read from its seller
// Account, with the edges from the Identifier to the domain.
func adsSeller(ctx context.Context, g graph.Graph, identID string) (string, string, []graph.WitnessEdge) {
	ids, err := g.Edges(ctx, identID, "in", "id", time.Time{})
	if err != nil {
		return "", "", nil
	}
	for _, ie := range ids {
		acct, err := g.GetAsset(ctx, ie.FromID)
		if err != nil || acct.Type != "Account" || graph.ContentString(acct, "account_type") != adsSellerAccount {
			continue
		}
		var sellerType string
		if ev, err := g.Evidence(ctx, acct.ID, 20); err == nil {
			if v := propertyValues(ev, adsPropSellerType); len(v) > 0 {
				sellerType = strings.ToUpper(v[0])
			}
		}
		idW := graph.WitnessEdge{EdgeID: ie.ID, Label: "id", RelationType: ie.Type, FromID: acct.ID,
			FromType: "Account", ToID: identID, ToType: "Identifier"}
		contacts, err := g.Edges(ctx, acct.ID, "out", "contact", time.Time{})
		if err != nil {
			return sellerType, "", nil
		}
		for _, ce := range contacts {
			doms, err := g.Edges(ctx, ce.ToID, "out", "fqdn", time.Time{})
			if err != nil {
				continue
			}
			for _, de := range doms {
				dom, err := g.GetAsset(ctx, de.ToID)
				if err != nil || graph.FQDNName(dom) == "" {
					continue
				}
				return sellerType, graph.FQDNName(dom), []graph.WitnessEdge{idW,
					{EdgeID: ce.ID, Label: "contact", RelationType: ce.Type, FromID: acct.ID, FromType: "Account",
						ToID: ce.ToID, ToType: "ContactRecord"},
					{EdgeID: de.ID, Label: "fqdn", RelationType: de.Type, FromID: ce.ToID, FromType: "ContactRecord",
						ToID: de.ToID, ToType: "FQDN", To: graph.FQDNName(dom)}}
			}
		}
		return sellerType, "", nil
	}
	return "", "", nil
}
