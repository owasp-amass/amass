// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"slices"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

var dnsJSON = semantics.File("dns.json")

type dnsRules struct {
	License           string   `json:"_license"`
	About             string   `json:"_about"`
	DNSPurpose        string   `json:"dns_purpose"`
	AddressTypes      []string `json:"address_types"`
	AliasRRTypes      []int    `json:"alias_rr_types"`
	DelegationRRTypes []int    `json:"delegation_rr_types"`
	MailRRTypes       []int    `json:"mail_rr_types"`
	MaxAliasDepth     int      `json:"max_alias_depth"`
}

var loadDNSRules = sync.OnceValue(func() dnsRules {
	var r dnsRules
	if err := graph.DecodeStrict(dnsJSON, &r); err != nil {
		panic("dns.json: " + err.Error())
	}
	if r.DNSPurpose == "" || len(r.AddressTypes) == 0 || len(r.AliasRRTypes) == 0 || r.MaxAliasDepth < 1 {
		panic("dns.json: dns_purpose, address_types, alias_rr_types and max_alias_depth are required")
	}

	return r
})

// resolution is what a stored name reaches through its DNS records.
type resolution struct {
	// Aliases are the names reached through alias records, in order; the
	// last is the name whose records were read last.
	Aliases []graph.Asset
	// Addresses are the stored addresses of the deepest name in the chain
	// that has any: the end of the chain normally, or an earlier name when
	// a flattened alias (an apex ANAME) stored its addresses there too.
	Addresses []graph.Asset
	// Loop is set when the chain returned to a name already in it, and
	// Deep when it was longer than max_alias_depth.
	Loop, Deep bool
}

// Aliased reports whether the name reaches anything through an alias.
func (r resolution) Aliased() bool { return len(r.Aliases) > 0 }

// Target is the last name of the alias chain, or the name itself.
func (r resolution) Target(name graph.Asset) graph.Asset {
	if len(r.Aliases) == 0 {
		return name
	}
	return r.Aliases[len(r.Aliases)-1]
}

// resolveName follows a name's stored DNS records: alias records to the
// names they point at, as a resolver does, and address records to the
// addresses stored for the last name reached. It reads only.
func resolveName(w *lensWalker, name graph.Asset) (resolution, error) {
	rules := loadDNSRules()
	var out resolution
	seen := map[string]bool{name.ID: true}
	cur := name
	for {
		steps, err := w.steps(cur)
		if err != nil {
			return out, err
		}

		var next *graph.Asset
		var addrs []graph.Asset
		for _, s := range steps {
			if !s.forward || s.purpose != rules.DNSPurpose {
				continue
			}
			switch {
			case slices.Contains(rules.AddressTypes, s.other.Type):
				addrs = append(addrs, s.other)
			case s.other.Type == cur.Type && slices.Contains(rules.AliasRRTypes, relationRRType(s.edge)) && next == nil:
				other := s.other
				next = &other
			}
		}
		if len(addrs) > 0 {
			out.Addresses = addrs
		}
		if next == nil {
			return out, nil
		}
		if seen[next.ID] {
			out.Loop = true
			return out, nil
		}
		if len(out.Aliases) == rules.MaxAliasDepth {
			out.Deep = true
			return out, nil
		}

		seen[next.ID] = true
		out.Aliases = append(out.Aliases, *next)
		cur = *next
	}
}

// mailRR reports whether a relation names a mail server (MX).
func mailRR(e graph.Relation) bool {
	return slices.Contains(loadDNSRules().MailRRTypes, relationRRType(e))
}

// delegationRR reports whether a relation is a delegation record (NS).
func delegationRR(e graph.Relation) bool {
	return slices.Contains(loadDNSRules().DelegationRRTypes, relationRRType(e))
}
