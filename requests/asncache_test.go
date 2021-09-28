// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package requests

import (
	"net"
	"testing"
	"time"
)

func TestEmpty(t *testing.T) {
	cache := NewASNCache()

	if entry := cache.ASNSearch(0); entry != nil {
		t.Errorf("ASNSearch returned a non-nil value when empty: %v", entry)
	}
	if entry := cache.AddrSearch("72.237.4.113"); entry != nil {
		t.Errorf("AddrSearch returned a non-nil value when empty: %v", entry)
	}
}

func TestUpdate(t *testing.T) {
	cache := NewASNCache()

	if entry := cache.AddrSearch("72.237.4.113"); entry != nil {
		t.Errorf("AddrSearch returned a non-nil value when empty: %v", entry)
	}

	cache.Update(&ASNRequest{
		Address: "72.237.4.113",
		ASN:     26808,
		Prefix:  "72.237.4.0/24",
		Tag:     RIR,
		Source:  "RIR",
	})

	if entry := cache.AddrSearch("72.237.4.113"); entry == nil {
		t.Errorf("AddrSearch returned nil after updated with the correct data")
	}

	cache.Update(&ASNRequest{
		Address:        "72.237.4.113",
		ASN:            26808,
		Prefix:         "72.237.4.0/24",
		CC:             "US",
		Registry:       "ARIN",
		AllocationDate: time.Now(),
		Description:    "UTICA-COLLEGE",
		Netblocks:      []string{"72.237.4.0/24", "8.24.68.0/23"},
		Tag:            RIR,
		Source:         "RIR",
	})

	if entry := cache.AddrSearch("72.237.4.113"); entry == nil || entry.CC != "US" || entry.Description != "UTICA-COLLEGE" {
		t.Errorf("Update failed to enhance the ASN entry with the more detailed data")
	}
	if entry := cache.AddrSearch("8.24.68.1"); entry == nil || entry.ASN != 26808 {
		t.Errorf("Update failed to add the new netblock to the ASN")
	}
}

func TestASNSearch(t *testing.T) {
	cache := NewASNCache()

	if entry := cache.ASNSearch(26808); entry != nil {
		t.Errorf("ASNSearch returned a non-nil value when empty: %v", entry)
	}

	cache.Update(&ASNRequest{
		Address: "72.237.4.113",
		ASN:     26808,
		Prefix:  "72.237.4.0/24",
		Tag:     RIR,
		Source:  "RIR",
	})

	if entry := cache.ASNSearch(26808); entry == nil {
		t.Errorf("ASNSearch returned nil after updated with the correct data")
	}
}

func TestAddrSearch(t *testing.T) {
	cache := NewASNCache()

	if entry := cache.AddrSearch("127.0.0.1"); entry == nil || entry.ASN != 0 {
		t.Errorf("AddrSearch returned nil when searching for a reserved network address block")
	}
	if entry := cache.AddrSearch("72.237.4.113"); entry != nil {
		t.Errorf("AddrSearch returned a non-nil value when empty: %v", entry)
	}

	cache.Update(&ASNRequest{
		Address:        "72.237.4.113",
		ASN:            26808,
		Prefix:         "72.237.4.0/24",
		CC:             "US",
		Registry:       "ARIN",
		AllocationDate: time.Now(),
		Description:    "UTICA-COLLEGE",
		Netblocks:      []string{"72.237.4.0/24", "8.24.68.0/23"},
		Tag:            RIR,
		Source:         "RIR",
	})

	if entry := cache.AddrSearch("72.237.4.120"); entry == nil {
		t.Errorf("AddrSearch returned nil after updated with the correct data")
	}

	addr := "8.24.68.1"
	ip := net.ParseIP(addr)
	entry := cache.AddrSearch(addr)
	if entry == nil {
		t.Fatalf("AddrSearch returned nil for an address known to the cache")
	}
	if _, ipnet, err := net.ParseCIDR(entry.Prefix); err != nil || !ipnet.Contains(ip) {
		t.Errorf("AddrSearch returned the wrong Prefix value for the provided IP address: %s", entry.Prefix)
	}
}
