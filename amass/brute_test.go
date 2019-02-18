// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"github.com/OWASP/Amass/amass/core"
	"github.com/miekg/dns"
)

var (
	domains  = []string{"claritysec.com", "twitter.com", "google.com", "github.com"}
	wordlist = []string{"foo", "bar"}

	// Resolved bruteTestRequests
	bruteTestRequests = []*core.Request{
		&core.Request{
			Name:    "test.claritysec.com",
			Domain:  "claritysec.com",
			Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
		},
		&core.Request{
			Name:    "test.twitter.com",
			Domain:  "twitter.com",
			Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
		},
		&core.Request{
			Name:    "test.google.com",
			Domain:  "google.com",
			Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
		},
		&core.Request{
			Name:    "test.github.com",
			Domain:  "github.com",
			Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
		},
	}
)

/*
func TestBruteForceRootDomains(t *testing.T) {
	config := &core.Config{}
	config.Wordlist = wordlist
	config.AddDomains(domains)
	config.BruteForcing = true

	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)

	out := make(chan *core.Request)
	bus := core.NewEventBus()
	bus.Subscribe(core.NewNameTopic, func(req *core.Request) {
		out <- req
	})
	defer bus.Stop()

	srv := NewBruteForceService(config, bus)
	srv.Start()
	defer srv.Stop()

	expected := len(config.Wordlist) * len(domains)
	results := make(map[string]int)
	done := time.After(time.Second)

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

func TestBruteForceMinForRecursive(t *testing.T) {
	config := &core.Config{}
	config.AddDomains(domains)
	config.Wordlist = wordlist
	config.BruteForcing = true
	config.Recursive = true
	config.MinForRecursive = 2

	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)

	out := make(chan *core.Request)
	bus := core.NewEventBus()
	bus.Subscribe(core.NewNameTopic, func(req *core.Request) {
		out <- req
	})
	defer bus.Stop()

	srv := NewBruteForceService(config, bus)
	srv.Start()
	defer srv.Stop()

	// Should be filtered
	bus.Publish(core.NewSubdomainTopic, bruteTestRequests[0], 1)

	// Should pass
	bus.Publish(core.NewSubdomainTopic, bruteTestRequests[1], 2)
	bus.Publish(core.NewSubdomainTopic, bruteTestRequests[2], 3)
	bus.Publish(core.NewSubdomainTopic, bruteTestRequests[3], 4)

	expected := len(config.Wordlist) * (len(bruteTestRequests) - 1 + len(domains))
	results := make(map[string]int)
	done := time.After(time.Second)

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
*/
