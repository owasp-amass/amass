// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"testing"
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
