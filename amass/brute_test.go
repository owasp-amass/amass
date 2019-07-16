// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build brute

package amass

import (
	"log"
	"strings"
	"testing"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/eventbus"
	"github.com/miekg/dns"
)

var (
	domains  = []string{"google.com"}
	wordlist = []string{"images", "search", "mail"}

	// Resolved bruteTestRequests
	bruteTestRequests = []*core.Request{
		&core.Request{
			Name:    "bing.com",
			Domain:  "bing.com",
			Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
		},
		&core.Request{
			Name:    "yahoo.com",
			Domain:  "yahoo.com",
			Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
		},
	}
)

func TestBruteForceRootDomains(t *testing.T) {
	config := &core.Config{}
	config.Wordlist = wordlist
	config.AddDomains(domains)
	config.BruteForcing = true

	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)

	out := make(chan *core.Request)
	bus := eventbus.NewEventBus()
	bus.Subscribe(core.NameResolvedTopic, func(req *core.Request) {
		out <- req
	})
	defer bus.Stop()

	srv := NewBruteForceService(config, bus)
	srv.Start()
	defer srv.Stop()

	count := 0
	expected := len(config.Wordlist) * len(domains)
	done := time.After(time.Second * 10)

loop:
	for {
		select {
		case <-out:
			count++
		case <-done:
			break loop
		}
	}

	if expected != count {
		t.Errorf("Got %d names, expected %d instead", count, expected)
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
	bus := eventbus.NewEventBus()
	bus.Subscribe(core.NameResolvedTopic, func(req *core.Request) {
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

	expected := len(config.Wordlist) * (len(bruteTestRequests) - 1 + len(domains))
	count := 0
	done := time.After(time.Second * 15)

loop:
	for {
		select {
		case <-out:
			count++
		case <-done:
			break loop
		}
	}

	if expected != count {
		t.Errorf("Got %d names, expected %d instead", count, expected)
	}
}
