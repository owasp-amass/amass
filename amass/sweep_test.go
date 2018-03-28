// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"testing"
)

func TestSweepService(t *testing.T) {
	in := make(chan *AmassRequest)
	out := make(chan *AmassRequest)
	config := DefaultConfig()
	config.Setup()

	srv := NewSweepService(in, out, config)

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
