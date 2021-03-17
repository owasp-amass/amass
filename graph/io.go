// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"net"

	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringfilter"
	"github.com/caffix/stringset"
	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/quad"
	"golang.org/x/net/publicsuffix"
)

type outLookup map[string]*requests.Output

// EventOutput returns findings within the receiver Graph for the event identified by the uuid string
// parameter and not already in the filter StringFilter argument. The filter is updated by EventOutput.
func (g *Graph) EventOutput(uuid string, filter stringfilter.Filter, asninfo bool, cache *requests.ASNCache) []*requests.Output {
	// Make sure a filter has been created
	if filter == nil {
		filter = stringfilter.NewStringFilter()
	}

	var names []string
	for _, name := range g.EventFQDNs(uuid) {
		if !filter.Has(name) {
			names = append(names, name)
		}
	}

	lookup := make(outLookup, len(names))
	for _, o := range g.buildNameInfo(uuid, names) {
		lookup[o.Name] = o
	}

	pairs, err := g.NamesToAddrs(uuid, names...)
	if err != nil {
		return nil
	}
	// Build the lookup map used to create the final result set
	for _, p := range pairs {
		if p.Name == "" || p.Addr == "" {
			continue
		}
		if o, found := lookup[p.Name]; found {
			o.Addresses = append(o.Addresses, requests.AddressInfo{Address: net.ParseIP(p.Addr)})
		}
	}

	if !asninfo || cache == nil {
		return removeDuplicates(lookup, filter)
	}
	return addInfrastructureInfo(lookup, filter, cache)
}

func removeDuplicates(lookup outLookup, filter stringfilter.Filter) []*requests.Output {
	output := make([]*requests.Output, 0, len(lookup))

	for _, o := range lookup {
		if !filter.Duplicate(o.Name) {
			output = append(output, o)
		}
	}

	return output
}

func addInfrastructureInfo(lookup outLookup, filter stringfilter.Filter, cache *requests.ASNCache) []*requests.Output {
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
		if len(o.Addresses) > 0 && !filter.Duplicate(o.Name) {
			output = append(output, o)
		}
	}

	return output
}

// EventNames returns findings within the receiver Graph for the event identified by the uuid string
// parameter and not already in the filter StringFilter argument. The filter is updated by EventNames.
func (g *Graph) EventNames(uuid string, filter stringfilter.Filter) []*requests.Output {
	// Make sure a filter has been created
	if filter == nil {
		filter = stringfilter.NewStringFilter()
	}

	var names []string
	for _, name := range g.EventFQDNs(uuid) {
		if !filter.Has(name) {
			names = append(names, name)
		}
	}

	var results []*requests.Output
	for _, o := range g.buildNameInfo(uuid, names) {
		if !filter.Duplicate(o.Name) {
			results = append(results, o)
		}
	}
	return results
}

func (g *Graph) buildNameInfo(uuid string, names []string) []*requests.Output {
	results := make(map[string]*requests.Output, len(names))

	var nameVals []quad.Value
	for _, name := range names {
		nameVals = append(nameVals, quad.IRI(name))
	}

	g.db.Lock()
	p := cayley.StartPath(g.db.store, nameVals...).Has(quad.IRI("type"), quad.String("fqdn"))
	p = p.Tag("name").InWithTags([]string{"predicate"}).Is(quad.IRI(uuid))
	err := p.Iterate(context.Background()).TagValues(nil, func(m map[string]quad.Value) {
		name := valToStr(m["name"])
		pred := valToStr(m["predicate"])

		if notDataSourceSet.Has(pred) {
			return
		}
		if _, found := results[name]; !found {
			results[name] = &requests.Output{Name: name}
		}

		n := append(results[name].Sources, pred)
		if s := stringset.Deduplicate(n); len(results[name].Sources) < len(s) {
			results[name].Sources = n
		}
	})
	g.db.Unlock()

	var final []*requests.Output
	if err != nil {
		return final
	}

	sourceTags := make(map[string]string)
	for _, o := range results {
		domain, err := publicsuffix.EffectiveTLDPlusOne(o.Name)
		if err != nil {
			continue
		}
		o.Domain = domain

		if len(o.Sources) == 0 {
			continue
		}
		o.Tag = g.selectTag(o.Sources, sourceTags)

		final = append(final, o)
	}
	return final
}

func (g *Graph) selectTag(sources []string, sourceTags map[string]string) string {
	var source, tag string

	for _, src := range sources {
		var found bool

		source = src
		tag, found = sourceTags[source]
		if !found {
			tag = g.SourceTag(source)
			sourceTags[source] = tag
		}

		if requests.TrustedTag(tag) {
			break
		}
	}

	return tag
}
