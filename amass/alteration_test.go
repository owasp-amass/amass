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

/*
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
}*/

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

func TestFlipNumbersInName(t *testing.T) {
	var (
		flipTestsRequests = []*core.Request{
			&core.Request{
				Name:    "test1.owasp.org",
				Domain:  "owasp.org",
				Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
			},
			&core.Request{
				Name:    "test2.twitter.com",
				Domain:  "twitter.com",
				Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
			},
		}
	)
	config := &core.Config{}
	config.Alterations = true
	for _, tests := range flipTestsRequests {
		config.AddDomain(tests.Domain)
	}

	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)
	bus := core.NewEventBus()
	as := NewAlterationService(config, bus)
	out := make(chan *core.Request)

	bus.Subscribe(core.NewNameTopic, func(req *core.Request) {
		out <- req
	})
	defer bus.Stop()

	for _, tests := range flipTestsRequests {
		as.flipNumbersInName(tests)
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
		expected := 11
		if len(results) != expected {
			t.Errorf("returned map only %v long, expected %v", len(results), expected)
		}
	}

}

func TestSecondNumberFlip(t *testing.T) {
	var (
		secondTestsRequests = []*core.Request{
			&core.Request{
				Name:    "test1.owasp.org",
				Domain:  "owasp.org",
				Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
			},
			&core.Request{
				Name:    "test2.twitter.com",
				Domain:  "twitter.com",
				Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
			},
		}
	)
	config := &core.Config{}
	config.Alterations = true
	for _, tests := range secondTestsRequests {
		config.AddDomain(tests.Domain)
	}

	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)
	bus := core.NewEventBus()
	as := NewAlterationService(config, bus)
	out := make(chan *core.Request)

	bus.Subscribe(core.NewNameTopic, func(req *core.Request) {
		out <- req
	})
	defer bus.Stop()

	for _, tests := range secondTestsRequests {
		as.secondNumberFlip(tests.Name, tests.Domain, -1)
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
		expected := 11
		if len(results) != expected {
			t.Errorf("returned map is %v long, expected %v", len(results), expected)
		}
	}

}

func TestAppendNumbers(t *testing.T) {
	var (
		appendTestsRequests = []*core.Request{
			&core.Request{
				Name:    "test1.owasp.org",
				Domain:  "owasp.org",
				Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
			},
			&core.Request{
				Name:    "test2.twitter.com",
				Domain:  "twitter.com",
				Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
			},
		}
	)
	config := &core.Config{}
	config.Alterations = true
	for _, tests := range appendTestsRequests {
		config.AddDomain(tests.Domain)
	}

	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)
	bus := core.NewEventBus()
	as := NewAlterationService(config, bus)
	out := make(chan *core.Request)

	bus.Subscribe(core.NewNameTopic, func(req *core.Request) {
		out <- req
	})
	defer bus.Stop()

	for _, tests := range appendTestsRequests {
		as.appendNumbers(tests)
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
		expected := 20
		if len(results) != expected {
			t.Errorf("returned map is %v long, expected %v", len(results), expected)
		}
	}
}

func TestSendAlteredName(t *testing.T) {
	var (
		appendTestsRequests = []*core.Request{
			&core.Request{
				Name:    "test1.owasp.org",
				Domain:  "owasp.org",
				Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
			},
			&core.Request{
				Name:    "test2.twitter.com",
				Domain:  "twitter.com",
				Records: []core.DNSAnswer{core.DNSAnswer{Type: int(dns.TypeA)}},
			},
		}
	)
	config := &core.Config{}
	config.Alterations = true
	for _, tests := range appendTestsRequests {
		config.AddDomain(tests.Domain)
	}

	buf := new(strings.Builder)
	config.Log = log.New(buf, "", log.Lmicroseconds)
	bus := core.NewEventBus()
	as := NewAlterationService(config, bus)
	out := make(chan *core.Request)

	bus.Subscribe(core.NewNameTopic, func(req *core.Request) {
		out <- req
	})
	defer bus.Stop()

	for _, tests := range appendTestsRequests {
		as.appendNumbers(tests)
		results := []string{}
		done := time.After(time.Second)

		bus.Publish(core.NameResolvedTopic, alterationTestRequests[0])

	loop:
		for {
			select {
			case req := <-out:
				results = append(results, req.Name)
			case <-done:
				break loop
			}
		}
		for _, change := range results {
			if strings.Contains(change, tests.Domain) != true {
				t.Errorf("Test %v found a unaltered name.", tests.Name)
			}

		}
	}

}
