// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
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
	// RecordTypeNames maps a stored record's numeric RR type to its label.
	RecordTypeNames map[int]string `json:"record_type_names"`
}

// recordTypeName is the label for a stored record's numeric RR type, or
// TYPE<number> when the type is not named in the configuration.
func (r dnsRules) recordTypeName(rr int) string {
	if name, ok := r.RecordTypeNames[rr]; ok {
		return name
	}

	return fmt.Sprintf("TYPE%d", rr)
}

// recordRRTypeEvidence bounds how many of a name's properties are read when
// gathering its record types.
const recordRRTypeEvidence = 100

// recordTypesOf returns the DNS record types stored on a name, as sorted
// labels. It reads both the name's record relations (A, AAAA, CNAME, NS, MX,
// SRV and the like, which point at another asset) and its record properties
// (TXT, CAA and the like, which have no target). An empty result means the
// name was discovered but no DNS record was verified for it, which the
// relations would otherwise prove.
func recordTypesOf(w *lensWalker, name graph.Asset) ([]string, error) {
	rules := loadDNSRules()
	set := map[string]bool{}

	steps, err := w.steps(name)
	if err != nil {
		return nil, err
	}
	for _, s := range steps {
		// A dns-purpose relation carries an RR type only when it is an actual
		// record; one with no type (verified_for, for example) is a different
		// kind of relationship, not a record, so skip it.
		if s.forward && s.purpose == rules.DNSPurpose {
			if rr := relationRRType(s.edge); rr != 0 {
				set[rules.recordTypeName(rr)] = true
			}
		}
	}

	evidence, err := w.graph.Evidence(w.ctx, name.ID, recordRRTypeEvidence)
	if err != nil {
		return nil, err
	}
	for _, ev := range evidence {
		if rr := dnsPropertyRRType(ev); rr != 0 {
			set[rules.recordTypeName(rr)] = true
		}
	}

	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// dnsPropertyRRType returns the RR type of a stored DNS record property, or 0
// when the evidence is not one.
func dnsPropertyRRType(ev graph.Evidence) int {
	data, err := json.Marshal(ev.Property)
	if err != nil {
		return 0
	}

	var p struct {
		Name   string `json:"property_name"`
		Header struct {
			RRType int `json:"rr_type"`
		} `json:"header"`
	}
	if json.Unmarshal(data, &p) != nil || p.Name != graph.DNSRecordProperty {
		return 0
	}

	return p.Header.RRType
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
