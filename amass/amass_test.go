// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"strconv"
	"testing"
)

const (
	testAddr string = "192.168.1.55"
	testCIDR string = "192.168.1.0/24"
)

func TestAmassRangeHosts(t *testing.T) {
	rng := &IPRange{
		Start: net.ParseIP("72.237.4.1"),
		End:   net.ParseIP("72.237.4.50"),
	}

	ips := RangeHosts(rng)
	if num := len(ips); num != 50 {
		t.Errorf("%d IP address strings were returned by RangeHosts instead of %d\n", num, 50)
	}
}

func TestAmassNetHosts(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("72.237.4.0/24")

	ips := NetHosts(ipnet)
	if num := len(ips); num != 254 {
		t.Errorf("%d IP address strings were returned by NetHosts instead of %d\n", num, 254)
	}
}

func TestAmassCIDRSubset(t *testing.T) {
	_, ipnet, err := net.ParseCIDR(testCIDR)
	if err != nil {
		t.Errorf("Unable to parse the CIDR: %s", err)
	}

	size := 50
	offset := size / 2
	subset := CIDRSubset(ipnet, testAddr, size)
	sslen := len(subset)

	if sslen != size+1 {
		t.Errorf("CIDRSubset returned an incorrect number of elements: %d", sslen)
	}

	if subset[0] != "192.168.1."+strconv.Itoa(55-offset) {
		t.Errorf("CIDRSubset did not return the correct first element: %s", subset[0])
	} else if subset[sslen-1] != "192.168.1."+strconv.Itoa(55+offset) {
		t.Errorf("CIDRSubset did not return the correct last element: %s", subset[sslen-1])
	}

	// Test the end of the slice edge case
	subset = CIDRSubset(ipnet, "192.168.1.250", size)
	sslen = len(subset)

	if sslen != offset+6 {
		t.Error("CIDRSubset returned an incorrect number of elements")
	}
}
