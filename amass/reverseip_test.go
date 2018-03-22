// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
)

func TestReverseIPBing(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := BingReverseIPSearch(out)

	go readOutput(out)
	req := &AmassRequest{Address: "72.237.4.113"}

	s.Search(req, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("BingReverseIPSearch found %d subdomain names", discovered)
	}
}

func TestReverseIPShodan(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := ShodanReverseIPSearch(out)

	go readOutput(out)
	req := &AmassRequest{Address: "72.237.4.113"}

	s.Search(req, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("ShodanReverseIPSearch found %d subdomain names", discovered)
	}
}

func TestReverseIPDNS(t *testing.T) {
	out := make(chan *AmassRequest, 2)
	finished := make(chan int, 2)
	s := ReverseDNSSearch(out)

	go readOutput(out)
	req := &AmassRequest{Address: "72.237.4.2"}

	s.Search(req, finished)
	discovered := <-finished
	if discovered <= 0 {
		t.Errorf("ReverseDNSSearch found %d PTR records", discovered)
	}
}

func readOutput(out chan *AmassRequest) {
	for {
		<-out
	}
}
