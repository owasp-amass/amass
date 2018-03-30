// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
	"time"
)

func TestReverseDNS(t *testing.T) {
	ip := "72.237.4.2"
	in := make(chan *AmassRequest, 2)
	out := make(chan *AmassRequest, 2)
	config := DefaultConfig()
	config.AddDomains([]string{"utica.edu"})
	config.Setup()

	s := NewReverseDNSService(in, out, config)
	s.Start()

	in <- &AmassRequest{Address: ip}

	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()

	select {
	case <-out:
		// Success
	case <-timeout.C:
		t.Errorf("ReverseDNSService timed out on the request for %s", ip)
	}

	s.Stop()
}
