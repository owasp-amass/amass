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
)

func setupConfig(domain string) *core.Config {
	config := &core.Config{}
	config.Alterations = true
	config.FlipWords = true
	config.AddWords = true
	config.FlipNumbers = true
	config.AddNumbers = true
	config.MinForWordFlip = 0
	config.EditDistance = 1
	config.AltWordlist = []string{"prod", "dev"}
	config.AddDomain(domain)
	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)

	return config
}

func setupEventBus(subscription string) (*core.EventBus, chan *core.Request) {
	out := make(chan *core.Request)
	bus := core.NewEventBus()
	bus.Subscribe(subscription, func(req *core.Request) {
		out <- req
	})

	return bus, out
}

func testService(srv core.Service, out chan *core.Request) int {
	srv.Start()
	defer srv.Stop()

	srv.SendRequest(alterationTestRequests[0])

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

	bus, out := setupEventBus(core.NewNameTopic)
	defer bus.Stop()

	srv := NewAlterationService(config, bus)

	count := testService(srv, out)
	expected := 450

	if count != expected {
		t.Errorf("Got %d names, expected %d instead", count, expected)
	}
}

func TestCorrectRecordTypes(t *testing.T) {
	var (
		alterationTestRequests = []*core.Request{
			&core.Request{
				Name:    "test1.owasp.org",
				Domain:  "owasp.org",
				Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
			},
			&core.Request{
				Name:    "test.twitter.com",
				Domain:  "twitter.com",
				Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
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
