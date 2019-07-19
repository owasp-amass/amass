// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build brute

package services

import (
	"log"
	"strings"
	"testing"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/resolvers"
	"github.com/miekg/dns"
)

var (
	domains  = []string{"google.com"}
	wordlist = []string{"images", "search", "mail"}

	// Resolved bruteTestRequests
	bruteTestRequests = []*DNSRequest{
		&Request{
			Name:    "bing.com",
			Domain:  "bing.com",
			Records: []DNSAnswer{DNSAnswer{Type: int(dns.TypeA)}},
		},
		&DNSRequest{
			Name:    "yahoo.com",
			Domain:  "yahoo.com",
			Records: []DNSAnswer{DNSAnswer{Type: int(dns.TypeA)}},
		},
	}
)

func TestBruteForceRootDomains(t *testing.T) {
	c := &config.Config{}
	c.Wordlist = wordlist
	c.AddDomains(domains)
	c.BruteForcing = true

	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)

	out := make(chan *DNSRequest)
	bus := eb.NewEventBus()
	bus.Subscribe(NameResolvedTopic, func(req *DNSRequest) {
		out <- req
	})
	defer bus.Stop()

	srv := NewBruteForceService(c, bus, resolvers.NewResolverPool(nil))
	srv.Start()
	defer srv.Stop()

	count := 0
	expected := len(c.Wordlist) * len(domains)
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
	c := &config.Config{}
	c.AddDomains(domains)
	c.Wordlist = wordlist
	c.BruteForcing = true
	c.Recursive = true
	c.MinForRecursive = 2

	buf := new(strings.Builder)
	c.Log = log.New(buf, "", log.Lmicroseconds)

	out := make(chan *DNSRequest)
	bus := eb.NewEventBus()
	bus.Subscribe(NameResolvedTopic, func(req *DNSRequest) {
		out <- req
	})
	defer bus.Stop()

	srv := NewBruteForceService(c, bus, resolvers.NewResolverPool(nil))
	srv.Start()
	defer srv.Stop()

	// Should be filtered
	bus.Publish(NewSubdomainTopic, bruteTestRequests[0], 1)

	// Should pass
	bus.Publish(NewSubdomainTopic, bruteTestRequests[1], 2)

	expected := len(c.Wordlist) * (len(bruteTestRequests) - 1 + len(domains))
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
