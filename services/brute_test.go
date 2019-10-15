// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"testing"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
)

var (
	domains  = []string{"google.com"}
	wordlist = []string{"images", "search", "mail"}

	// Resolved bruteTestRequests
	bruteTestRequests = []*requests.DNSRequest{
		&requests.DNSRequest{
			Name:   "www.bing.com",
			Domain: "bing.com",
		},
		&requests.DNSRequest{
			Name:   "www.yahoo.com",
			Domain: "yahoo.com",
		},
	}
)

func TestBruteForceRootDomains(t *testing.T) {
	if *networkTest == false {
		return
	}

	cfg := config.NewConfig()
	cfg.Wordlist = wordlist
	cfg.AddDomains(domains)
	cfg.BruteForcing = true

	sys, err := NewLocalSystem(cfg)
	if err != nil {
		return
	}
	defer sys.Shutdown()

	bus := eb.NewEventBus()
	defer bus.Stop()

	ctx := context.WithValue(context.Background(), requests.ContextConfig, cfg)
	ctx = context.WithValue(ctx, requests.ContextEventBus, bus)

	out := make(chan *requests.DNSRequest)
	fn := func(req *requests.DNSRequest) {
		out <- req
	}
	bus.Subscribe(requests.NameResolvedTopic, fn)
	defer bus.Unsubscribe(requests.NameResolvedTopic, fn)

	var srv Service
	for _, s := range testSystem.DataSources() {
		if s.String() == "Brute Forcing" {
			srv = s
			break
		}
	}
	if srv == nil {
		return
	}

	for _, d := range cfg.Domains() {
		srv.DNSRequest(ctx, &requests.DNSRequest{
			Name:   d,
			Domain: d,
		})
	}

	count := 0
	expected := len(cfg.Wordlist) * len(domains)
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
	if *networkTest == false {
		return
	}

	cfg := config.NewConfig()
	cfg.Wordlist = wordlist
	cfg.AddDomains(domains)
	cfg.BruteForcing = true
	cfg.Recursive = true
	cfg.MinForRecursive = 2

	sys, err := NewLocalSystem(cfg)
	if err != nil {
		return
	}
	defer sys.Shutdown()

	bus := eb.NewEventBus()
	defer bus.Stop()

	ctx := context.WithValue(context.Background(), requests.ContextConfig, cfg)
	ctx = context.WithValue(ctx, requests.ContextEventBus, bus)

	out := make(chan *requests.DNSRequest)
	fn := func(req *requests.DNSRequest) {
		out <- req
	}
	bus.Subscribe(requests.NameResolvedTopic, fn)
	defer bus.Unsubscribe(requests.NameResolvedTopic, fn)

	var srv Service
	for _, s := range testSystem.DataSources() {
		if s.String() == "Brute Forcing" {
			srv = s
			break
		}
	}
	if srv == nil {
		return
	}

	// Should be filtered
	srv.SubdomainDiscovered(ctx, bruteTestRequests[0], 1)

	// Should pass
	srv.SubdomainDiscovered(ctx, bruteTestRequests[1], 2)

	expected := len(cfg.Wordlist)
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
