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

func TestSweepService(t *testing.T) {
	in := make(chan *AmassRequest)
	out := make(chan *AmassRequest)
	srv := NewSweepService(in, out, DefaultConfig())

	_, ipnet, err := net.ParseCIDR(testCIDR)
	if err != nil {
		t.Errorf("Unable to parse the CIDR: %s", err)
	}

	srv.Start()
	in <- &AmassRequest{
		Address:  testAddr,
		Netblock: ipnet,
	}

	for i := 0; i < 51; i++ {
		<-out
	}

	srv.Stop()
}

func TestSweepGetCIDRSubset(t *testing.T) {
	_, ipnet, err := net.ParseCIDR(testCIDR)
	if err != nil {
		t.Errorf("Unable to parse the CIDR: %s", err)
	}

	ips := NetHosts(ipnet)

	size := 50
	offset := size / 2
	subset := getCIDRSubset(ips, testAddr, size)
	sslen := len(subset)

	if sslen != size+1 {
		t.Errorf("getCIDRSubset returned an incorrect number of elements: %d", sslen)
	}

	if subset[0] != "192.168.1."+strconv.Itoa(55-offset) {
		t.Errorf("getCIDRSubset did not return the correct first element: %s", subset[0])
	} else if subset[sslen-1] != "192.168.1."+strconv.Itoa(55+offset) {
		t.Errorf("getCIDRSubset did not return the correct last element: %s", subset[sslen-1])
	}

	// Test the end of the slice edge case
	subset = getCIDRSubset(ips, "192.168.1.250", size)
	sslen = len(subset)

	if sslen != offset+5 {
		t.Error("getCIDRSubset returned an incorrect number of elements")
	}
}
