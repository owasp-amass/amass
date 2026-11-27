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

// Infrastructure correlation associates more netblocks and autonomous systems
// with a target organization, the IP-space counterpart of the horizontal
// related-domains lens. This read-only lens surfaces the netblocks and ASes the
// infrastructure signals tie to an organization, each with the evidence and a
// confidence, for a person (or the scored scope-expansion) to decide on — it
// never grows scope itself (ai-design-principles.md, principles 10 & 13).
//
// The signals, each from a Regional Internet Registry registration already in
// the Asset Database:
//   - shared netblock registrant organization: a netblock whose IPNetRecord
//     registration names the organization;
//   - shared AS registrant organization: an autonomous system whose AutnumRecord
//     registration names the organization.
//
// A WHOIS privacy proxy or a placeholder organization is shared by many
// unrelated registrations, so such a subject is never correlated on.

// asnSmallNetblocks is the most prefixes an organization's AS may announce
// for its announcements to be the strong small-AS signal: an enterprise or
// campus network announces a handful, a transit or hosting network many.
const asnSmallNetblocks = 32

// InfrastructureAsset is a netblock or autonomous system an infrastructure
// signal ties to the subject organization, with the evidence and confidence
// behind it. AssetType is the OAM type ("Netblock" or "AutonomousSystem") and
// Asset its key (a CIDR, or an AS number).
type InfrastructureAsset struct {
	AssetType  string              `json:"asset_type"`
	Asset      string              `json:"asset"`
	Confidence int                 `json:"confidence"`
	Signals    []string            `json:"signals"`
	SignalIDs  []string            `json:"signal_ids,omitempty"`
	Witness    []graph.WitnessEdge `json:"witness,omitempty"`
	// ContributedSignals are the strong signals among SignalIDs that rest
	// on what assistants contributed; they score as supporting
	// (contributionJudge).
	ContributedSignals []string `json:"contributed_signals,omitempty"`
}

// RelatedInfrastructureReport is the result of an infrastructure-correlation
// search for one organization.
type RelatedInfrastructureReport struct {
	OrgID     string                `json:"org_id"`
	Org       string                `json:"org"`
	Assets    []InfrastructureAsset `json:"assets"`
	Truncated string                `json:"truncated,omitempty"`
}

// FindRelatedInfrastructure finds the netblocks and autonomous systems the
// infrastructure signals tie to an organization, read-only. It returns nothing
// for a privacy proxy or a placeholder organization (principle 8).
func FindRelatedInfrastructure(ctx context.Context, g graph.Graph, orgID string) (RelatedInfrastructureReport, error) {
	org, err := g.GetAsset(ctx, orgID)
	if err != nil {
		return RelatedInfrastructureReport{}, err
	}
	if org.Type != "Organization" {
		return RelatedInfrastructureReport{}, fmt.Errorf("%s is not an Organization", orgID)
	}

	name := graph.ContentString(org, "name")
	report := RelatedInfrastructureReport{OrgID: orgID, Org: name}
	if name == "" || registrant.IsPrivacyProxyName(name) || semantics.IsPlaceholderOrganization(name) {
		return report, nil
	}

	acc := map[string]*InfrastructureAsset{}
	witnesses := signalWitnesses{}
	add := func(assetType, asset, signalID, signal string, witness ...graph.WitnessEdge) {
		asset = strings.ToLower(strings.TrimSpace(asset))
		if asset == "" {
			return
		}
		key := assetType + "\x00" + asset
		a, ok := acc[key]
		if !ok {
			a = &InfrastructureAsset{AssetType: assetType, Asset: asset}
			acc[key] = a
		}
		if !slices.Contains(a.SignalIDs, signalID) {
			a.SignalIDs = append(a.SignalIDs, signalID)
		}
		if !slices.Contains(a.Signals, signal) {
			a.Signals = append(a.Signals, signal)
		}
		a.Witness = append(a.Witness, witness...)
		witnesses.add(key, signalID, witness)
	}

	contacts, err := g.Edges(ctx, orgID, "in", "organization", time.Time{})
	if err != nil {
		return report, err
	}
	// the organization's autonomous systems and netblocks found below, for
	// the routing security signals that start from them
	ownAS := map[string]graph.WitnessEdge{}
	ownASNumbers := map[string]bool{}
	ownNetblocks := map[string]bool{}

	ipnetSig := "shared netblock registrant organization: " + name
	asnSig := "shared AS registrant organization: " + name
	announceSig := "announced by an AS registered to: " + name
	orgWitness := func(ce graph.Relation) graph.WitnessEdge {
		return graph.WitnessEdge{EdgeID: ce.ID, Label: "organization", RelationType: ce.Type,
			FromID: ce.FromID, FromType: "ContactRecord", ToID: ce.ToID, ToType: "Organization", To: name}
	}

	for _, ce := range contacts {
		// IPNetRecord / AutnumRecord --registrant--> ContactRecord.
		records, err := g.Edges(ctx, ce.FromID, "in", "registrant", time.Time{})
		if err != nil {
			return report, err
		}
		for _, re := range records {
			rec, err := g.GetAsset(ctx, re.FromID)
			if err != nil {
				continue
			}
			switch rec.Type {
			case "IPNetRecord":
				w := graph.WitnessEdge{EdgeID: re.ID, Label: "registrant", RelationType: re.Type,
					FromID: re.FromID, FromType: "IPNetRecord", ToID: re.ToID, ToType: "ContactRecord"}
				add("Netblock", graph.ContentString(rec, "cidr"), SigIPNetRegistrantOrg, ipnetSig,
					w, orgWitness(ce))
				if nbs, err := g.Edges(ctx, re.FromID, "in", "registration", time.Time{}); err == nil {
					for _, ne := range nbs {
						ownNetblocks[ne.FromID] = true
					}
				}
			case "DomainRecord":
				// the mail senders the organization's domains declare
				apexes, err := g.Edges(ctx, re.FromID, "in", "registration", time.Time{})
				if err != nil {
					continue
				}
				for _, ae := range apexes {
					spfRanges(ctx, g, ae.FromID, name, add)
				}
			case "AutnumRecord":
				w := graph.WitnessEdge{EdgeID: re.ID, Label: "registrant", RelationType: re.Type,
					FromID: re.FromID, FromType: "AutnumRecord", ToID: re.ToID, ToType: "ContactRecord"}
				add("AutonomousSystem", graph.ContentString(rec, "number"), SigASNRegistrantOrg, asnSig,
					w, orgWitness(ce))
				// Corroboration: netblocks the organization's AS announces.
				// AutonomousSystem --registration--> AutnumRecord, so the AS is
				// reached by the incoming registration edge; its announced
				// prefixes are a supporting signal (announcement is operation,
				// not registration).
				ases, err := g.Edges(ctx, re.FromID, "in", "registration", time.Time{})
				if err != nil {
					continue
				}
				for _, ae := range ases {
					regW := graph.WitnessEdge{EdgeID: ae.ID, Label: "registration", RelationType: ae.Type,
						FromID: ae.FromID, FromType: "AutonomousSystem", ToID: ae.ToID, ToType: "AutnumRecord"}
					ownAS[ae.FromID] = regW
					if as, err := g.GetAsset(ctx, ae.FromID); err == nil {
						ownASNumbers["AS"+graph.ContentString(as, "number")] = true
					}
					anns, err := g.Edges(ctx, ae.FromID, "out", "announces", time.Time{})
					if err != nil {
						continue
					}
					annSigID, annLabel := SigASNAnnouncedNetblock, announceSig
					if len(anns) <= asnSmallNetblocks {
						annSigID = SigSmallASNAnnounced
						annLabel = fmt.Sprintf("announced by an AS registered to %s that announces %d prefixes",
							name, len(anns))
					}
					for _, ann := range anns {
						nb, err := g.GetAsset(ctx, ann.ToID)
						if err != nil {
							continue
						}
						ownNetblocks[ann.ToID] = true
						annW := graph.WitnessEdge{EdgeID: ann.ID, Label: "announces", RelationType: ann.Type,
							FromID: ann.FromID, FromType: "AutonomousSystem", ToID: ann.ToID, ToType: "Netblock"}
						add("Netblock", graph.ContentString(nb, "cidr"), annSigID, annLabel, regW, annW)
					}
				}
			}
		}
	}

	routingSecurity(ctx, g, name, ownAS, ownASNumbers, ownNetblocks, add)

	report.Assets = make([]InfrastructureAsset, 0, len(acc))
	judge := newContributionJudge(ctx, g)
	for key, a := range acc {
		a.ContributedSignals = witnesses.contributed(judge, key, a.SignalIDs, LookupInfrastructureSignal)
		a.Confidence, _ = InfrastructureScore(a.SignalIDs, a.ContributedSignals)
		report.Assets = append(report.Assets, *a)
	}
	sort.Slice(report.Assets, func(i, j int) bool {
		if report.Assets[i].AssetType != report.Assets[j].AssetType {
			return report.Assets[i].AssetType < report.Assets[j].AssetType
		}
		return report.Assets[i].Asset < report.Assets[j].Asset
	})
	return report, nil
}

// InfrastructureExpansion partitions a related-infrastructure report into the
// assets a strong signal justifies adding to scope (expand) and corroboration-
// only ones that need review, the same decision as HorizontalExpansion.
func InfrastructureExpansion(r RelatedInfrastructureReport) (expand, needsReview []InfrastructureAsset) {
	for _, a := range r.Assets {
		if _, strong := InfrastructureScore(a.SignalIDs, a.ContributedSignals); strong {
			expand = append(expand, a)
		} else {
			needsReview = append(needsReview, a)
		}
	}

	return expand, needsReview
}

// FormatRelatedInfrastructureReport renders an infrastructure search for a
// terminal.
func FormatRelatedInfrastructureReport(r RelatedInfrastructureReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Related infrastructure for %s [%s]", r.Org, r.OrgID)
	if r.Truncated != "" {
		fmt.Fprintf(&b, " (truncated: %s)", r.Truncated)
	}
	b.WriteString("\n")
	if len(r.Assets) == 0 {
		b.WriteString("No related infrastructure found.\n")
		return b.String()
	}
	for _, a := range r.Assets {
		fmt.Fprintf(&b, "  %s %s (confidence %d): %s\n", a.AssetType, a.Asset, a.Confidence,
			strings.Join(a.Signals, ", "))
	}

	return b.String()
}
