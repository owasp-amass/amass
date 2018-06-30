// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

/*
import (
	"testing"
	"time"
)

func TestDNSService(t *testing.T) {
	config := DefaultConfig()
	config.AddDomains([]string{testDomain})

	s := NewDNSService(config)
	s.Start()

	name := "www." + testDomain
	s.SendRequest(&AmassRequest{
		Name:   name,
		Domain: testDomain,
	})

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
*/
