// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"log"
	"strings"
	"testing"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/miekg/dns"
)

var (
	alterationTestRequests = []*requests.DNSRequest{
		&requests.DNSRequest{
			Name:    "test1.owasp.org",
			Domain:  "owasp.org",
			Records: []requests.DNSAnswer{requests.DNSAnswer{Type: int(dns.TypeA)}},
		},
	}
)

func setupConfig(domain string) *config.Config {
	cfg := &config.Config{}
	cfg.Alterations = true
	cfg.FlipWords = true
	cfg.AddWords = true
	cfg.FlipNumbers = true
	cfg.AddNumbers = true
	cfg.MinForWordFlip = 0
	cfg.EditDistance = 1
	cfg.AltWordlist = []string{"prod", "dev"}
	cfg.AddDomain(domain)
	buf := new(strings.Builder)
	cfg.Log = log.New(buf, "", log.Lmicroseconds)

	return cfg
}

func setupEventBus(subscription string) (*eb.EventBus, chan *requests.DNSRequest) {
	out := make(chan *requests.DNSRequest)
	bus := eb.NewEventBus()
	bus.Subscribe(subscription, func(req *requests.DNSRequest) {
		out <- req
	})

	return bus, out
}

func testService(srv Service, out chan *requests.DNSRequest) int {
	srv.Start()
	defer srv.Stop()

	srv.SendDNSRequest(alterationTestRequests[0])

	count := 0
	doneTimer := time.After(time.Second * 3)

	time.Sleep(time.Second * 1)
	go srv.LowNumberOfNames()
loop:
	for {
		select {
		case <-out:
			count++
		case <-doneTimer:
			break loop
		}
	}

	return count
}

func TestAlterations(t *testing.T) {
	config := setupConfig("owasp.org")

	bus, out := setupEventBus(requests.NewNameTopic)
	defer bus.Stop()

	srv := NewAlterationService(config, bus, resolvers.NewResolverPool(nil))

	count := testService(srv, out)
	expected := 450

	if count != expected {
		t.Errorf("Got %d names, expected %d instead", count, expected)
	}
}

func TestCorrectRecordTypes(t *testing.T) {
	var (
		alterationTestRequests = []*requests.DNSRequest{
			&requests.DNSRequest{
				Name:    "test1.owasp.org",
				Domain:  "owasp.org",
				Records: []requests.DNSAnswer{requests.DNSAnswer{Type: int(dns.TypeA)}},
			},
			&requests.DNSRequest{
				Name:    "test.twitter.com",
				Domain:  "twitter.com",
				Records: []requests.DNSAnswer{requests.DNSAnswer{Type: int(dns.TypeA)}},
			},
		}
	)

	expected := true
	for _, tests := range alterationTestRequests {
		as := new(AlterationService)
		foo := as.correctRecordTypes(tests)
		if foo != expected {
			t.Errorf("correctRecordtype() in %v returned %v, expected %v", tests.Name, foo, expected)
		}
	}
}
