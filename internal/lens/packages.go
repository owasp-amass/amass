// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	"github.com/owasp-amass/amass/v5/internal/semantics/cloudranges"
)

// Package registry evidence (engine plugin packages): a registry namespace is
// joined to the domain it is tied to (namespace_domain: the domain a Maven
// groupId names, which Maven Central verified, or the domain of the addresses
// that maintain an npm namespace), and to its packages, whose website
// relations carry the role of each URL (url_role).
const (
	packageAccountType = "package_namespace"
	packagePropURLRole = "url_role"
	packageRoleOrg     = "organization"
	packageMavenPrefix = "maven:"
)

// packagePivot finds the other registered domains the organization's
// published packages name. From each of the organization's domains it follows
// the registry namespaces tied to the domain to their packages and the URLs
// those name. The organization URL of a package in a Maven group named for
// the domain is the strong signal: Maven Central verified the group's domain,
// and the package names the publisher's own site. Any other URL a package
// names (its homepage, project page or repository) is supporting.
func packagePivot(ctx context.Context, g graph.Graph, ownApexes, ownDomains []string,
	add func(string, string, string, ...graph.WitnessEdge)) {
	er, _ := g.(graph.EdgeEvidenceReader)
	seen := map[string]bool{}
	for _, apexID := range ownApexes {
		tied, err := g.Edges(ctx, apexID, "in", "namespace_domain", time.Time{})
		if err != nil {
			continue
		}
		for _, te := range tied {
			if seen[te.FromID] {
				continue
			}
			seen[te.FromID] = true
			ns, err := g.GetAsset(ctx, te.FromID)
			if err != nil || graph.ContentString(ns, "account_type") != packageAccountType {
				continue
			}
			maven := strings.HasPrefix(graph.ContentString(ns, "unique_id"), packageMavenPrefix)
			tiedW := graph.WitnessEdge{EdgeID: te.ID, Label: "namespace_domain", RelationType: te.Type,
				FromID: te.FromID, FromType: "Account", ToID: te.ToID, ToType: "FQDN"}

			products, err := g.Edges(ctx, ns.ID, "out", "package", time.Time{})
			if err != nil {
				continue
			}
			for _, pe := range products {
				pkgW := graph.WitnessEdge{EdgeID: pe.ID, Label: "package", RelationType: pe.Type,
					FromID: pe.FromID, FromType: "Account", ToID: pe.ToID, ToType: "Product"}
				packageURLs(ctx, g, er, pe.ToID, maven, ownDomains, add, tiedW, pkgW)
			}
		}
	}
}

// packageURLs adds the registered domains of the URLs one package names.
func packageURLs(ctx context.Context, g graph.Graph, er graph.EdgeEvidenceReader, productID string, maven bool,
	ownDomains []string, add func(string, string, string, ...graph.WitnessEdge),
	witness ...graph.WitnessEdge) {
	sites, err := g.Edges(ctx, productID, "out", "website", time.Time{})
	if err != nil {
		return
	}
	for _, se := range sites {
		u, err := g.GetAsset(ctx, se.ToID)
		if err != nil {
			continue
		}
		host := strings.ToLower(graph.ContentString(u, "host"))
		apex := graph.RegisteredDomain(host)
		if apex == "" || withinAny(host, ownDomains) || !publisherHost(host) {
			continue
		}

		role := ""
		if er != nil {
			if ev, err := er.EdgeEvidence(ctx, se.ID, 20); err == nil {
				if v := propertyValues(ev, packagePropURLRole); len(v) > 0 {
					role = v[0]
				}
			}
		}
		if role == "" {
			role = "website"
		}
		sig, label := SigPackageWebsite, "named by the organization's package ("+role+")"
		if maven && role == packageRoleOrg {
			sig, label = SigPackageOrganization, "the publisher's site in the organization's verified Maven group"
		}
		siteW := graph.WitnessEdge{EdgeID: se.ID, Label: "website", RelationType: se.Type,
			FromID: se.FromID, FromType: "Product", ToID: se.ToID, ToType: "URL"}
		add(apex, sig, label, append(append([]graph.WitnessEdge{}, witness...), siteW)...)
	}
}

// publisherHost reports whether a host a package names can be its publisher's
// own: not a shared platform (a code host, a registry's site), a domain that
// gives each project a subdomain (example.github.io), or a cloud provider's
// hosting domain.
func publisherHost(host string) bool {
	if SharedPlatformHost(host) || semantics.PackageRegistryCatalog().HostingDomain(host) {
		return false
	}
	_, cloud := cloudranges.ProviderByDomain(host)
	return !cloud
}
