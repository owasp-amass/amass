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
	"github.com/owasp-amass/amass/v5/internal/semantics/cloudranges"
)

// LensCloud asks which public cloud and CDN providers host a domain or
// organization's names, by provider, region and service, from the ranges the
// providers publish. The answer is built in Go from stored attributions;
// nothing is written.
const LensCloud = "cloud"

// cloudExamples bounds the example names kept per provider.
const cloudExamples = 3

var cloudLens = SubjectLens{
	Name:    LensCloud,
	Command: "cloud",
	Description: "Show the public cloud and CDN providers hosting a domain or organization's names, by provider, " +
		"region and service, from the providers' own published IP ranges. Read-only",
	Examples: []string{"What cloud providers host <domain>?",
		"Which of <organization>'s names are on AWS, and in which regions?",
		"Is <domain> all in one cloud region?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindCloud(ctx, g, schema, root, opts.Limits)
	},
}

// CloudProviderShare is how many of the subject's names one provider hosts,
// with the regions, services and networks they resolve into.
type CloudProviderShare struct {
	Provider string   `json:"provider"`
	Names    int      `json:"names"`
	Regions  []string `json:"regions,omitempty"`
	Services []string `json:"services,omitempty"`
	Networks []string `json:"networks,omitempty"`
	Examples []string `json:"examples,omitempty"`
}

// CloudReport is the result of the cloud lens.
type CloudReport struct {
	lensBase
	// Providers are the cloud and CDN providers hosting the subject's names,
	// most names first. OnCloud counts the names on a recognized provider,
	// Resolving those with any stored address, and Names all controlled names.
	Providers []CloudProviderShare `json:"providers"`
	OnCloud   int                  `json:"on_cloud"`
	Resolving int                  `json:"resolving"`
	Names     int                  `json:"names"`
}

// FindCloud lists the cloud and CDN providers hosting a domain or
// organization's names, from the provider attributions stored on the
// netblocks their addresses fall in. It reads only.
func FindCloud(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (CloudReport, error) {
	g = graph.Cached(g)
	var out CloudReport
	s, err := newScope(ctx, g, schema, root, limits, LensCloud)
	if err != nil {
		return out, err
	}

	d := dependencyScan{w: s.w, owned: s.owned, ownDomains: s.ownDomains, ownNets: s.ownNets}
	byProv := map[string]*CloudProviderShare{}
	counted := map[string]bool{}
	var order []string

	// record adds one of the subject's names to a provider's share, counting
	// the name once per provider however many of its addresses that provider
	// holds.
	record := func(provider string, name graph.Asset, cidr, region, service string) {
		sh, ok := byProv[provider]
		if !ok {
			sh = &CloudProviderShare{Provider: provider}
			byProv[provider] = sh
			order = append(order, provider)
		}
		if cidr != "" {
			graph.AddUnique(&sh.Networks, cidr)
		}
		if region != "" {
			graph.AddUnique(&sh.Regions, region)
		}
		if service != "" {
			graph.AddUnique(&sh.Services, service)
		}
		if key := provider + "\x00" + name.ID; !counted[key] {
			counted[key] = true
			sh.Names++
			if len(sh.Examples) < cloudExamples {
				graph.AddUnique(&sh.Examples, graph.FQDNName(name))
			}
		}
	}

	for _, id := range s.order {
		if s.spent() {
			break
		}
		name := s.owned[id]
		if name.Type != "FQDN" {
			continue
		}
		out.Names++

		res, err := resolveName(s.w, name)
		if err != nil {
			return out, err
		}
		if len(res.Addresses) > 0 || res.Aliased() {
			out.Resolving++
		}

		onCloud := false
		// An address whose hosting party is a recognized cloud/CDN provider,
		// attributed the same way the network lens attributes hosting (by the
		// party that operates the address), then classified against the
		// provider catalog. This catches cloud hosting recorded only through
		// registration, with no provider edge written.
		for _, addr := range res.Addresses {
			block, err := d.blockOf(addr)
			if err != nil {
				return out, err
			}
			target := addr
			if block.ID != "" {
				target = block
			}
			label, _, own, _, err := d.party(target)
			if err != nil {
				return out, err
			}
			if own || label == "" {
				continue
			}
			p, ok := cloudranges.ProviderByName(label)
			if !ok {
				continue
			}

			onCloud = true
			region, service := "", ""
			if block.ID != "" {
				region, service = graph.CloudMeta(s.w.ctx, s.w.graph, block.ID)
			}
			record(p.Organization, name, graph.ContentString(block, "cidr"), region, service)
		}

		// A name aliased (CNAME) to a provider-operated domain is fronted by
		// that provider even when its final address was never resolved, which
		// is the common shape of edge and CDN hosting (Azure Front Door,
		// CloudFront, Fastly, GitHub Pages).
		if res.Aliased() {
			dom := graph.RegisteredDomain(graph.FQDNName(res.Target(name)))
			if p, ok := cloudranges.ProviderByDomain(dom); ok {
				onCloud = true
				record(p.Organization, name, "", "", "")
			}
		}

		if onCloud {
			out.OnCloud++
		}
	}

	for _, k := range order {
		sh := byProv[k]
		sort.Strings(sh.Regions)
		sort.Strings(sh.Services)
		sort.Strings(sh.Networks)
		out.Providers = append(out.Providers, *sh)
	}
	sort.SliceStable(out.Providers, func(i, j int) bool {
		if out.Providers[i].Names != out.Providers[j].Names {
			return out.Providers[i].Names > out.Providers[j].Names
		}
		return out.Providers[i].Provider < out.Providers[j].Provider
	})
	out.lensBase = s.base()
	return out, nil
}

// blockOf returns the netblock a stored address is in: one stored as
// containing it, or the most specific netblock whose range holds it when the
// graph can search ranges.
func (d dependencyScan) blockOf(ip graph.Asset) (graph.Asset, error) {
	steps, err := d.w.steps(ip)
	if err != nil {
		return graph.Asset{}, err
	}
	for _, s := range steps {
		if !s.forward && s.other.Type == "Netblock" {
			return s.other, nil
		}
	}

	return d.w.netblockByRange(ip)
}

// Text implements Report.
func (r CloudReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Cloud and CDN hosting of %s: %d of %d name(s) on a recognized provider "+
		"(%d resolving, %d reads).\n", subject, r.OnCloud, r.Names, r.Resolving, r.Reads)

	if len(r.Providers) == 0 {
		b.WriteString("\nNo name resolves into a recognized cloud or CDN provider's published range.\n")
		b.WriteString("These are stored attributions, not a live scan." + r.partialNote() + "\n")
		return b.String()
	}

	b.WriteString("\n")
	for _, p := range r.Providers {
		fmt.Fprintf(&b, "  %s: %d name(s)", p.Provider, p.Names)
		if len(p.Regions) > 0 {
			fmt.Fprintf(&b, ", regions: %s", strings.Join(p.Regions, ", "))
		}
		if len(p.Services) > 0 {
			fmt.Fprintf(&b, ", services: %s", strings.Join(p.Services, ", "))
		}
		if len(p.Examples) > 0 {
			fmt.Fprintf(&b, ", e.g. %s", strings.Join(p.Examples, ", "))
		}
		b.WriteString("\n")
	}

	b.WriteString("\nThese are stored attributions from the providers' published ranges, not a live scan." +
		r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r CloudReport) Facts() []string {
	out := make([]string, 0, len(r.Providers))
	for _, p := range r.Providers {
		fact := fmt.Sprintf("%d name(s) on %s", p.Names, p.Provider)
		if len(p.Regions) > 0 {
			fact += " (" + strings.Join(p.Regions, ", ") + ")"
		}
		out = append(out, fact)
	}

	return out
}
