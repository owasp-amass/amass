// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
	"time"
)

func TestDNSService(t *testing.T) {
	in := make(chan *AmassRequest, 2)
	out := make(chan *AmassRequest, 2)
	config := DefaultConfig()
	config.AddDomains([]string{testDomain})
	config.Setup()

	s := NewDNSService(in, out, config)
	s.Start()

	name := "www." + testDomain
	in <- &AmassRequest{
		Name:   name,
		Domain: testDomain,
	}

	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	select {
	case <-out:
		// Success
	case <-timeout.C:
		t.Errorf("DNSService timed out on the request for %s", name)
	}

	s.Stop()
}

func TestDNSQuery(t *testing.T) {
	name := "google.com"
	config := DefaultConfig()
	config.Setup()

	answers, err := config.dns.Query(name)
	if err != nil {
		t.Errorf("The DNS query for %s failed: %s", name, err)
	}

	if ip := GetARecordData(answers); ip == "" {
		t.Errorf("The query for %s was successful, yet did not return a A or AAAA record", name)
	}
}
