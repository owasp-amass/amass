// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package net

import (
	"net"
	"strconv"
	"testing"
)

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		Address  string
		Expected bool
	}{
		{"72.237.4.0", true},
		{"192.168.1.0", true},
		{"174.129.0.0:80", true},
		{"0.0.0.0", true},
		{"2620:0:860:2::", false},
		{"2620:0:860:2:ffff:ffff:ffff:ffff", false},
	}

	for _, test := range tests {
		if b := IsIPv4(net.ParseIP(test.Address)); b != test.Expected {
			t.Errorf("Failed on IP address %s", test.Address)
		}
	}
}

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		Address  string
		Expected bool
	}{
		{"72.237.4.0", false},
		{"192.168.1.0", false},
		{"174.129.0.0:80", false},
		{"0.0.0.0", false},
		{"2620:0:860:2::", true},
		{"2620:0:860:2:ffff:ffff:ffff:ffff", true},
	}

	for _, test := range tests {
		if b := IsIPv6(net.ParseIP(test.Address)); b != test.Expected {
			t.Errorf("Failed on IP address %s", test.Address)
		}
	}
}

func TestFirstLast(t *testing.T) {
	tests := []struct {
		CIDR          string
		ExpectedFirst string
		ExpectedLast  string
	}{
		{"72.237.4.0/24", "72.237.4.0", "72.237.4.255"},
		{"192.168.1.0/24", "192.168.1.0", "192.168.1.255"},
		{"174.129.0.0/16", "174.129.0.0", "174.129.255.255"},
		{"0.0.0.0/0", "0.0.0.0", "255.255.255.255"},
		{"192.168.1.0/32", "192.168.1.0", "192.168.1.0"},
		{"2620:0:860:2::/64", "2620:0:860:2::", "2620:0:860:2:ffff:ffff:ffff:ffff"},
	}

	for _, test := range tests {
		_, ipnet, _ := net.ParseCIDR(test.CIDR)

		if f, l := FirstLast(ipnet); f.String() != test.ExpectedFirst || l.String() != test.ExpectedLast {
			t.Errorf("Returned first IP %s and last IP %s instead of %s and %s, respectively",
				f.String(), l.String(), test.ExpectedFirst, test.ExpectedLast)
		}
	}
}

func TestRange2CIDR(t *testing.T) {
	tests := []struct {
		First    string
		Last     string
		Expected string
	}{
		{"72.237.4.0", "72.237.4.255", "72.237.4.0/24"},
		{"192.168.1.0", "192.168.1.255", "192.168.1.0/24"},
		{"174.129.0.0", "174.129.255.255", "174.129.0.0/16"},
		{"0.0.0.0", "255.255.255.255", "0.0.0.0/0"},
		{"192.168.1.0", "192.168.1.0", "192.168.1.0/32"},
		{"2620:0:860:2::", "2620:0:860:2:ffff:ffff:ffff:ffff", "2620:0:860:2::/64"},
	}

	// A start IP greater than the end IP should return nil
	nocidr := Range2CIDR(net.ParseIP("192.168.1.255"), net.ParseIP("192.168.1.1"))
	if nocidr != nil {
		t.Errorf("Failed to return nil when %s was greater than %s", "192.168.1.255", "192.168.1.1")
	}

	for _, test := range tests {
		cidr := Range2CIDR(net.ParseIP(test.First), net.ParseIP(test.Last))

		if cidr == nil {
			t.Errorf("First IP %s and last IP %s failed to return %s",
				test.First, test.Last, test.Expected)
		} else if cidr.String() != test.Expected {
			t.Errorf("First IP %s and last IP %s returned %s instead of %s",
				test.First, test.Last, cidr.String(), test.Expected)
		}
	}
}

func TestAllHosts(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("72.237.4.0/24")

	hosts := AllHosts(ipnet)
	if n := len(hosts); n != 254 {
		t.Errorf("%d hosts were returned instead of %d", n, 254)
	}

	num := 1
	s := "72.237.4."
	for _, host := range hosts {
		ip := s + strconv.Itoa(num)

		if ip != host.String() {
			t.Errorf("IP address %s was missing from the slice of returned hosts", ip)
		}

		num++
	}
}

func TestRangeHosts(t *testing.T) {
	tests := []struct {
		First        string
		Last         string
		ExpectedSize int
	}{
		{"72.237.4.1", "72.237.4.50", 50},
		{"192.168.2.1", "192.168.2.1", 1},
		{"192.168.1.25", "192.168.1.1", 0},
		{"150.154.1.250", "150.154.2.50", 57},
		{"2620:0:860:2::", "2620:0:860:2::7d", 126},
	}

	for _, test := range tests {
		hosts := RangeHosts(net.ParseIP(test.First), net.ParseIP(test.Last))

		if num := len(hosts); num != test.ExpectedSize {
			t.Errorf("Range %s - %s caused %d hosts to be returned instead of %d",
				test.First, test.Last, num, test.ExpectedSize)
		} else if num == 0 {
			continue
		}

		ip := net.ParseIP(test.First)
		for _, host := range hosts {
			if ip.String() != host.String() {
				t.Errorf("IP address %s was missing from the slice of returned hosts", ip.String())
			}

			IPInc(ip)
		}

		IPDec(ip)
		if ip.String() != test.Last {
			t.Errorf("The last IP %s did not match the expected IP %s", ip.String(), test.Last)
		}
	}

	if num := len(RangeHosts(nil, nil)); num != 0 {
		t.Errorf("nil IP addresses caused %d hosts to be returned instead of 0", num)
	}
}

func TestCIDRSubset(t *testing.T) {
	tests := []struct {
		CIDR          string
		Address       string
		Size          int
		ExpectedFirst string
		ExpectedLast  string
		ExpectedSize  int
	}{
		{"192.168.1.0/24", "192.168.1.55", 50, "192.168.1.30", "192.168.1.80", 51},
		{"72.237.4.0/24", "72.237.4.0", 200, "72.237.4.0", "72.237.4.100", 101},
		{"72.237.4.0/24", "72.237.4.250", 200, "72.237.4.150", "72.237.4.255", 106},
		{"192.168.1.0/24", "192.168.2.1", 100, "192.168.2.1", "192.168.2.1", 1},
		{"192.168.1.0/32", "192.168.1.0", 20, "192.168.1.0", "192.168.1.0", 1},
		{"2620:0:860:2::/64", "2620:0:860:2::", 250, "2620:0:860:2::", "2620:0:860:2::7d", 126},
	}

	for _, test := range tests {
		_, ipnet, _ := net.ParseCIDR(test.CIDR)

		subset := CIDRSubset(ipnet, test.Address, test.Size)
		if l := len(subset); l != test.ExpectedSize {
			t.Errorf("The returned subset had %d elements instead of %d", l, test.ExpectedSize)
		}

		cur := net.ParseIP(test.ExpectedFirst)
		for _, ip := range subset {
			if cur.String() != ip.String() {
				t.Errorf("IP address %s was missing from the slice of returned addresses", cur.String())
			}

			IPInc(cur)
		}

		IPDec(cur)
		if cur.String() != test.ExpectedLast {
			t.Errorf("The last IP in the subset %s did not match the expected IP %s", cur.String(), test.ExpectedLast)
		}
	}
}

func TestIPInc(t *testing.T) {
	tests := []struct {
		Address  string
		Expected string
	}{
		{"72.237.4.0", "72.237.4.1"},
		{"192.168.1.255", "192.168.2.0"},
		{"174.128.255.255", "174.129.0.0"},
		{"0.0.0.0", "0.0.0.1"},
	}

	for _, test := range tests {
		ip := net.ParseIP(test.Address)

		IPInc(ip)
		if ip.String() != test.Expected {
			t.Errorf("%s caused %s to be returned instead of %s", test.Address, ip.String(), test.Expected)
		}
	}
}

func TestIPDec(t *testing.T) {
	tests := []struct {
		Address  string
		Expected string
	}{
		{"72.237.4.1", "72.237.4.0"},
		{"192.168.1.0", "192.168.0.255"},
		{"174.129.0.0", "174.128.255.255"},
		{"0.0.0.1", "0.0.0.0"},
	}

	for _, test := range tests {
		ip := net.ParseIP(test.Address)

		IPDec(ip)
		if ip.String() != test.Expected {
			t.Errorf("%s caused %s to be returned instead of %s", test.Address, ip.String(), test.Expected)
		}
	}
}
