// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strconv"
	"testing"

	"github.com/caffix/recon"
)

func TestPublicServers(t *testing.T) {
	name := "www.claritysec.com"

	for _, server := range nameservers {
		_, err := recon.ResolveDNS(name, server, "A")
		if err != nil {
			t.Errorf("Public DNS server (%s) failed to resolve (%s)", server, name)
		}
	}
}

func TestDNSRequestQueue(t *testing.T) {
	a := NewAmass()

	// The queue should be empty
	if a.DNSRequestQueueEmpty() != true {
		t.Error("DNSRequestQueueEmpty returned: false for an empty queue")
	}

	// Add a new entry into the queue
	sd := Subdomain{
		Name:   "www.claritysec.com",
		Domain: "claritysec.com",
		Tag:    "dns",
	}

	a.AddDNSRequest(&sd)

	// Now, the queue should not be empty
	if a.DNSRequestQueueEmpty() == true {
		t.Error("DNSRequestQueueEmpty returned: true after adding an entry")
	}

	// Check that the request added is returned by NextDNSRequest
	if next := a.NextDNSRequest(); next == nil || next.Name != sd.Name {
		t.Errorf("NextDNSRequest did not return the one entry: %v", sd)
	}

	// The queue should be empty again
	if a.DNSRequestQueueEmpty() != true {
		t.Error("DNSRequestQueueEmpty returned: false for an empty queue")
	}
}

func TestGetCIDR(t *testing.T) {
	var answers []recon.DNSAnswer

	a := NewAmass()
	name := "www.claritysec.com"
	server := nameservers[0]

	// Lets get the IP address for a known name first
	ans, err := recon.ResolveDNS(name, server, "A")
	if err != nil {
		t.Error("Failed to resolve the name: ", name)
	}
	answers = append(answers, ans)

	// Now we can get the CIDR data related to the IP address
	ipstr := recon.GetARecordData(answers)
	if ipstr == "" {
		t.Errorf("No A record data was returned for %s", name)
	}

	data, cached := a.GetCIDR(ipstr)
	// The data should not have been in the cache this time
	if data == nil {
		t.Error("GetCIDR return nil for the CIDR data")
	} else if cached == true {
		t.Error("GetCIDR indicated the data was cached the first time we requested it")
	}

	// The data should be cached this time
	data, cached = a.GetCIDR(ipstr)
	if data == nil {
		t.Error("GetCIDR return nil for the CIDR data")
	} else if cached == false {
		t.Error("GetCIDR indicated the data was not cached the second time we requested it")
	}
}

func TestGetCIDRSubset(t *testing.T) {
	var hosts []string

	a := NewAmass()
	// Generate a slice of sequentual IP addresses
	for i := 0; i < 256; i++ {
		ip := "192.168.1." + strconv.Itoa(i)

		hosts = append(hosts, ip)
	}

	size := 50
	offset := size / 2
	addr := 100
	first, last := addr-offset, addr+offset
	subset := a.getCIDRSubset(hosts, "192.168.1."+strconv.Itoa(addr), size)
	sslen := len(subset)

	if sslen != size+1 {
		t.Error("getCIDRSubset returned an incorrect number of elements")
	}

	if subset[0] != "192.168.1."+strconv.Itoa(first) {
		t.Errorf("getCIDRSubset did not return the correct first element: %s", subset[0])
	} else if subset[sslen-1] != "192.168.1."+strconv.Itoa(last) {
		t.Errorf("getCIDRSubset did not return the correct last element: %s", subset[sslen-1])
	}

	// Test the end of the slice edge case
	addr = 250
	first, last = addr-offset, addr+offset
	subset = a.getCIDRSubset(hosts, "192.168.1."+strconv.Itoa(addr), size)
	sslen = len(subset)

	if sslen != offset+6 {
		t.Error("getCIDRSubset returned an incorrect number of elements")
	}
}
