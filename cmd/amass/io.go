// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"math/rand"
	"net"
	"time"

	"github.com/OWASP/Amass/v3/enum"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/netmap"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
	"golang.org/x/net/publicsuffix"
)

var sourceTags map[string]string

func init() {
	sourceTags = make(map[string]string)
}

// ExtractOutput is a convenience method for obtaining new discoveries made by the enumeration process.
func ExtractOutput(ctx context.Context, g *netmap.Graph, e *enum.Enumeration, filter *stringset.Set, asinfo bool, limit int) []*requests.Output {
	if e.Config.Passive {
		return EventNames(ctx, g, e.Config.UUID.String(), filter)
	}
	return EventOutput(ctx, g, e.Config.UUID.String(), filter, asinfo, e.Sys.Cache(), limit)
}

type outLookup map[string]*requests.Output

// EventOutput returns findings within the receiver Graph for the event identified by the uuid string
// parameter and not already in the filter argument. The filter is updated by EventOutput.
func EventOutput(ctx context.Context, g *netmap.Graph, uuid string, f *stringset.Set, asninfo bool, cache *requests.ASNCache, limit int) []*requests.Output {
	// Make sure a filter has been created
	if f == nil {
		f = stringset.New()
		defer f.Close()
	}

	var fqdns []string
	for _, name := range g.EventFQDNs(ctx, uuid) {
		if !f.Has(name) {
			fqdns = append(fqdns, name)
		}
	}

	names := randomSelection(fqdns, limit)
	lookup := make(outLookup, len(names))
	for _, o := range buildNameInfo(ctx, g, uuid, names) {
		lookup[o.Name] = o
	}
	// Build the lookup map used to create the final result set
	if pairs, err := g.NamesToAddrs(ctx, uuid, names...); err == nil {
		for _, p := range pairs {
			if p.Name == "" || p.Addr == "" {
				continue
			}
			if o, found := lookup[p.Name]; found {
				o.Addresses = append(o.Addresses, requests.AddressInfo{Address: net.ParseIP(p.Addr)})
			}
		}
	}

	if !asninfo || cache == nil {
		return removeDuplicates(lookup, f)
	}
	return addInfrastructureInfo(lookup, f, cache)
}

func randomSelection(names []string, limit int) []string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	var sel []string
	for i, n := range r.Perm(len(names)) {
		if limit > 0 && i >= limit {
			break
		}

		sel = append(sel, names[n])
	}
	return sel
}

func removeDuplicates(lookup outLookup, filter *stringset.Set) []*requests.Output {
	output := make([]*requests.Output, 0, len(lookup))

	for _, o := range lookup {
		if !filter.Has(o.Name) {
			output = append(output, o)
			filter.Insert(o.Name)
		}
	}
	return output
}

func addInfrastructureInfo(lookup outLookup, filter *stringset.Set, cache *requests.ASNCache) []*requests.Output {
	output := make([]*requests.Output, 0, len(lookup))

	for _, o := range lookup {
		var newaddrs []requests.AddressInfo

		for _, a := range o.Addresses {
			i := cache.AddrSearch(a.Address.String())
			if i == nil {
				continue
			}

			_, netblock, _ := net.ParseCIDR(i.Prefix)
			newaddrs = append(newaddrs, requests.AddressInfo{
				Address:     a.Address,
				ASN:         i.ASN,
				CIDRStr:     i.Prefix,
				Netblock:    netblock,
				Description: i.Description,
			})
		}

		o.Addresses = newaddrs
		if len(o.Addresses) > 0 && !filter.Has(o.Name) {
			output = append(output, o)
			filter.Insert(o.Name)
		}
	}
	return output
}

// EventNames returns findings within the receiver Graph for the event identified by the uuid string
// parameter and not already in the filter argument. The filter is updated by EventNames.
func EventNames(ctx context.Context, g *netmap.Graph, uuid string, f *stringset.Set) []*requests.Output {
	// Make sure a filter has been created
	if f == nil {
		f = stringset.New()
		defer f.Close()
	}

	var names []string
	for _, name := range g.EventFQDNs(ctx, uuid) {
		if !f.Has(name) {
			names = append(names, name)
		}
	}

	var results []*requests.Output
	for _, o := range buildNameInfo(ctx, g, uuid, names) {
		if !f.Has(o.Name) {
			results = append(results, o)
			f.Insert(o.Name)
		}
	}
	return results
}

func buildNameInfo(ctx context.Context, g *netmap.Graph, uuid string, names []string) []*requests.Output {
	results := make(map[string]*requests.Output, len(names))

	for _, name := range names {
		if _, found := results[name]; found {
			continue
		}

		n := netmap.Node(name)
		if srcs, err := g.NodeSources(ctx, n, uuid); err == nil && len(srcs) > 0 {
			results[name] = &requests.Output{
				Name:    name,
				Sources: srcs,
			}
		}
	}

	var final []*requests.Output
	for _, o := range results {
		d, err := publicsuffix.EffectiveTLDPlusOne(o.Name)
		if err != nil {
			continue
		}
		o.Domain = d

		o.Tag = selectTag(o.Sources)
		final = append(final, o)
	}
	return final
}

func initializeSourceTags(srcs []service.Service) {
	sourceTags["DNS"] = requests.DNS
	sourceTags["Reverse DNS"] = requests.DNS
	sourceTags["NSEC Walk"] = requests.DNS
	sourceTags["DNS Zone XFR"] = requests.AXFR
	sourceTags["Active Crawl"] = requests.CRAWL
	sourceTags["Active Cert"] = requests.CERT

	for _, src := range srcs {
		sourceTags[src.String()] = src.Description()
	}
}

func selectTag(sources []string) string {
	var trusted, others []string

	for _, src := range sources {
		tag, found := sourceTags[src]
		if !found {
			continue
		}

		if requests.TrustedTag(tag) {
			trusted = append(trusted, tag)
		} else {
			others = append(others, tag)
		}
	}

	tags := others
	if len(trusted) > 0 {
		tags = trusted
	}

	if len(tags) == 0 {
		return requests.DNS
	}

	sel := 0
	if m := len(tags); m > 0 {
		sel = rand.Int() % m
	}

	return tags[sel]
}
