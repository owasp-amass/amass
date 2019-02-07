// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"log"
	"strings"
	"testing"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/miekg/dns"
)

var (
	alterationTestRequests = []*core.Request{
		&core.Request{
			Name:    "test1.owasp.org",
			Domain:  "owasp.org",
			Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
		},
	}

	alterationTestExpected = []string{
		"test.owasp.org",
		"test0.owasp.org", "test1.owasp.org", "test2.owasp.org", "test3.owasp.org", "test4.owasp.org", "test5.owasp.org", "test6.owasp.org", "test7.owasp.org", "test8.owasp.org", "test9.owasp.org",
		"test10.owasp.org", "test11.owasp.org", "test12.owasp.org", "test13.owasp.org", "test14.owasp.org", "test15.owasp.org", "test16.owasp.org", "test17.owasp.org", "test18.owasp.org", "test19.owasp.org",
		"test1-0.owasp.org", "test1-1.owasp.org", "test1-2.owasp.org", "test1-3.owasp.org", "test1-4.owasp.org", "test1-5.owasp.org", "test1-6.owasp.org", "test1-7.owasp.org", "test1-8.owasp.org", "test1-9.owasp.org",
	}
)

func TestAlterations(t *testing.T) {
	config := &core.Config{}
	config.Alterations = true
	// insert config options here
	for _, req := range alterationTestRequests {
		config.AddDomain(req.Domain)
	}

	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)

	out := make(chan *core.Request)
	bus := core.NewEventBus()
	bus.Subscribe(core.NewNameTopic, func(req *core.Request) {
		out <- req
	})
	defer bus.Stop()

	srv := NewAlterationService(config, bus)
	srv.Start()
	defer srv.Stop()

	expected := len(alterationTestExpected)
	results := make(map[string]int)
	done := time.After(time.Second)

	bus.Publish(core.NameResolvedTopic, alterationTestRequests[0])

loop:
	for {
		select {
		case req := <-out:
			results[req.Name]++
		case <-done:
			break loop
		}
	}

	if expected != len(results) {
		t.Errorf("Got %d names, expected %d instead", len(results), expected)
	}
}
