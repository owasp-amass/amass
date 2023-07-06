// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net"

	"github.com/caffix/netmap"
	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v3/enum"
	"github.com/owasp-amass/amass/v3/requests"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"golang.org/x/net/publicsuffix"
)

// ExtractOutput is a convenience method for obtaining new discoveries made by the enumeration process.
func ExtractOutput(ctx context.Context, g *netmap.Graph, e *enum.Enumeration, filter *stringset.Set, asinfo bool) []*requests.Output {
	if e.Config.Passive {
		return EventNames(ctx, g, e.Config.Domains(), filter)
	}
	return EventOutput(ctx, g, e.Config.Domains(), filter, asinfo, e.Sys.Cache())
}

type outLookup map[string]*requests.Output

// EventOutput returns findings within the receiver Graph within the scope identified by the provided domain names.
// The filter is updated by EventOutput.
func EventOutput(ctx context.Context, g *netmap.Graph, domains []string, f *stringset.Set, asninfo bool, cache *requests.ASNCache) []*requests.Output {
	var res []*requests.Output

	if len(domains) == 0 {
		return res
	}
	// Make sure a filter has been created
	if f == nil {
		f = stringset.New()
		defer f.Close()
	}

	var fqdns []oam.Asset
	for _, d := range domains {
		fqdns = append(fqdns, domain.FQDN{Name: d})
	}

	assets, err := g.DB.FindByScope(fqdns...)
	if err != nil {
		return res
	}

	var names []string
	for _, a := range assets {
		if n, ok := a.Asset.(domain.FQDN); ok && !f.Has(n.Name) {
			names = append(names, n.Name)
		}
	}

	lookup := make(outLookup, len(names))
	for _, n := range names {
		d, err := publicsuffix.EffectiveTLDPlusOne(n)
		if err != nil {
			continue
		}

		o := &requests.Output{
			Name:   n,
			Domain: d,
		}
		res = append(res, o)
		lookup[n] = o
	}
	// Build the lookup map used to create the final result set
	if pairs, err := g.NamesToAddrs(ctx, names...); err == nil {
		for _, p := range pairs {
			addr := p.Addr.Address.String()

			if p.FQDN.Name == "" || addr == "" {
				continue
			}
			if o, found := lookup[p.FQDN.Name]; found {
				o.Addresses = append(o.Addresses, requests.AddressInfo{Address: net.ParseIP(addr)})
			}
		}
	}

	if !asninfo || cache == nil {
		return removeDuplicates(lookup, f)
	}
	return addInfrastructureInfo(lookup, f, cache)
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

// EventNames returns findings within the receiver Graph within the scope identified by the provided domain names.
// The filter is updated by EventNames.
func EventNames(ctx context.Context, g *netmap.Graph, domains []string, f *stringset.Set) []*requests.Output {
	var res []*requests.Output

	if len(domains) == 0 {
		return res
	}
	// Make sure a filter has been created
	if f == nil {
		f = stringset.New()
		defer f.Close()
	}

	var fqdns []oam.Asset
	for _, d := range domains {
		fqdns = append(fqdns, domain.FQDN{Name: d})
	}

	assets, err := g.DB.FindByScope(fqdns...)
	if err != nil {
		return res
	}

	var names []string
	for _, a := range assets {
		if n, ok := a.Asset.(domain.FQDN); ok && !f.Has(n.Name) {
			names = append(names, n.Name)
			f.Insert(n.Name)
		}
	}

	for _, n := range names {
		d, err := publicsuffix.EffectiveTLDPlusOne(n)
		if err != nil {
			continue
		}

		res = append(res, &requests.Output{
			Name:   n,
			Domain: d,
		})
	}
	return res
}
