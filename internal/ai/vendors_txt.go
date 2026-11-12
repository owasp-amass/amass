// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

//go:embed semantics/txt_vendors.json
var txtVendorsJSON []byte

type txtVendorRules struct {
	License       string `json:"_license"`
	About         string `json:"_about"`
	Verifications []struct {
		Vendor   string   `json:"vendor"`
		Prefixes []string `json:"prefixes"`
	} `json:"verifications"`
	SPFSenders []struct {
		Vendor  string   `json:"vendor"`
		Domains []string `json:"domains"`
	} `json:"spf_senders"`
}

var loadTXTVendors = sync.OnceValue(func() txtVendorRules {
	var r txtVendorRules
	if err := decodeStrict(txtVendorsJSON, &r); err != nil {
		panic("txt_vendors.json: " + err.Error())
	}

	return r
})

// Vendor kinds found in TXT records.
const (
	kindVerification = "SaaS: domain verification (DNS TXT)"
	kindSPF          = "Email: authorized senders (SPF)"
)

// txtValues returns the TXT record values stored for an asset.
func txtValues(ctx context.Context, graph Graph, id string) ([]string, error) {
	evidence, err := graph.Evidence(ctx, id, 100)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, e := range evidence {
		data, err := json.Marshal(e.Property)
		if err != nil {
			continue
		}

		var p struct {
			Name   string `json:"property_name"`
			Header struct {
				RRType int `json:"rr_type"`
			} `json:"header"`
			Data string `json:"data"`
		}
		if json.Unmarshal(data, &p) == nil && p.Name == dnsRecordProperty && p.Header.RRType == rrTypeTXT &&
			p.Data != "" {
			out = append(out, strings.Trim(p.Data, `"`))
		}
	}

	return out, nil
}

// txtVendors finds the services a domain's TXT records name: verification
// tokens and SPF senders.
func txtVendors(records []string, domain string) []VendorUse {
	rules := loadTXTVendors()
	found := map[string]*VendorUse{}
	add := func(vendor, kind, via string) {
		key := kind + "\x00" + vendor
		if _, ok := found[key]; !ok {
			found[key] = &VendorUse{Vendor: vendor, Kind: kind, Via: via, Assets: 1, Examples: []string{domain}}
		}
	}

	for _, rec := range records {
		lower := strings.ToLower(strings.TrimSpace(rec))
		for _, v := range rules.Verifications {
			for _, p := range v.Prefixes {
				if strings.HasPrefix(lower, strings.ToLower(p)) {
					add(v.Vendor, kindVerification, "TXT "+p)
				}
			}
		}

		if !strings.HasPrefix(lower, "v=spf1") {
			continue
		}
		for _, mech := range strings.Fields(lower) {
			target := ""
			switch {
			case strings.HasPrefix(mech, "include:"):
				target = strings.TrimPrefix(mech, "include:")
			case strings.HasPrefix(mech, "+include:"):
				target = strings.TrimPrefix(mech, "+include:")
			case strings.HasPrefix(mech, "redirect="):
				target = strings.TrimPrefix(mech, "redirect=")
			default:
				continue
			}
			target = strings.TrimSuffix(target, ".")

			for _, s := range rules.SPFSenders {
				for _, d := range s.Domains {
					if target == d || strings.HasSuffix(target, "."+d) {
						add(s.Vendor, kindSPF, "SPF include:"+target)
					}
				}
			}
		}
	}

	out := make([]VendorUse, 0, len(found))
	for _, v := range found {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Vendor < out[j].Vendor
	})

	return out
}

// FindVendors lists the outside parties a domain and its organization's
// controlled assets depend on: the third-party lens over stored
// relationships, and the services the domain's TXT records name. root is
// the domain's FQDN. It reads only.
func FindVendors(ctx context.Context, graph Graph, schema SchemaCatalog, root Asset) (ThirdPartyReport, error) {
	if root.Type != "FQDN" {
		return ThirdPartyReport{}, errors.New("the vendors lens starts from a domain name")
	}

	r, err := searchThirdParties(ctx, graph, schema, root)
	if err != nil {
		return r, err
	}

	records, err := txtValues(ctx, graph, root.ID)
	if err != nil {
		return r, fmt.Errorf("TXT records of %s: %w", assetLabel(root), err)
	}

	r.Vendors = append(r.Vendors, txtVendors(records, fqdnName(root))...)
	return r, nil
}

// FormatVendorReport renders a vendors report for a terminal.
func FormatVendorReport(r ThirdPartyReport) string {
	return thirdPartyAnswer(r) + "\n"
}
