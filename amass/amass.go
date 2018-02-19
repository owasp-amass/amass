// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
	"time"
)

const (
	// Tags used to mark the data source with the Subdomain struct
	SMART   = "smart"
	ALT     = "alteration"
	BRUTE   = "brute"
	SEARCH  = "search"
	ARCHIVE = "archive"

	// The default size of the channels within the Amass struct
	defaultAmassChanSize = 500

	// The number of goroutines fired off by each amass instantiation
	numberofProcessingRoutines = 5

	// This regular expression + the base domain will match on all names and subdomains
	SUBRE = "(([a-zA-Z0-9]{1}|[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"
)

// Amass - Contains amass state information
type Amass struct {
	// The slice that contains words to use when generating names
	Wordlist []string

	// Sets the maximum number of DNS queries per minute
	Frequency time.Duration

	// The channel to send names on for DNS resolution and other processing
	Names chan *Subdomain

	// The channel that will receive names that have been successfully resolved
	Resolved chan *Subdomain

	// Requests for the next DNS server to use are sent here
	nextNameserver chan chan string

	// Tells the processNextNameserver goroutine to quit
	nextNameserverQuit chan struct{}

	// New DNS requests are sent through this channel
	addDNSRequest chan *Subdomain

	// Requests are sent through this channel to check if the queue is empty
	dnsRequestQueueEmpty chan chan bool

	// Tells the processDNSRequests goroutine to quit
	dnsRequestsQuit chan struct{}

	// Requests are sent through this channel for CIDR information
	getCIDRInfo chan *getCIDR

	// Tells the processGetCIDR goroutine to quit
	getCIDRQuit chan struct{}

	// Requests are sent through this channel to check DNS wildcard matches
	wildcardMatches chan *wildcard

	// Tells the processWildcardMatches goroutine to quit
	wildcardMatchesQuit chan struct{}

	// Requests to check the reverse DNS filter are sent through this channel
	checkRDNSFilter chan *reverseDNSFilter

	// Tells the processReverseDNSFilter goroutine to quit
	reverseDNSFilterQuit chan struct{}

	// Goroutines indicates completion on this channel
	done chan struct{}
}

// Subdomain - Contains information about a subdomain name
type Subdomain struct {
	// The discovered subdomain name
	Name string

	// The base domain that the name belongs to
	Domain string

	// The IP address that the name resolves to
	Address string

	// The data source that discovered the name within the amass package
	Tag string
}

// NewAmass - Returns an Amass struct initialized with the default configuration
func NewAmass() *Amass {
	return NewAmassWithConfig(DefaultConfig())
}

// NewAmassWithConfig - Returns an Amass struct initialized with a custom configuration
func NewAmassWithConfig(ac AmassConfig) *Amass {
	config := customConfig(ac)

	a := &Amass{
		Wordlist:             config.Wordlist,
		Frequency:            config.Frequency,
		Names:                make(chan *Subdomain, defaultAmassChanSize),
		Resolved:             make(chan *Subdomain, defaultAmassChanSize),
		nextNameserver:       make(chan chan string, defaultAmassChanSize),
		nextNameserverQuit:   make(chan struct{}, 2),
		addDNSRequest:        make(chan *Subdomain, defaultAmassChanSize),
		dnsRequestQueueEmpty: make(chan chan bool, defaultAmassChanSize),
		dnsRequestsQuit:      make(chan struct{}, 2),
		getCIDRInfo:          make(chan *getCIDR, defaultAmassChanSize),
		getCIDRQuit:          make(chan struct{}, 2),
		wildcardMatches:      make(chan *wildcard, defaultAmassChanSize),
		wildcardMatchesQuit:  make(chan struct{}, 2),
		checkRDNSFilter:      make(chan *reverseDNSFilter, defaultAmassChanSize),
		reverseDNSFilterQuit: make(chan struct{}, 2),
		done:                 make(chan struct{}, numberofProcessingRoutines),
	}
	// Start all the goroutines
	go a.initialize()
	return a
}

func (a *Amass) initialize() {
	go a.processNextNameserver()
	go a.processDNSRequests()
	go a.processWildcardMatches()
	go a.processGetCIDR()
	go a.processReverseDNSFilter()
}

func (a *Amass) Clean() {
	a.nextNameserverQuit <- struct{}{}
	a.dnsRequestsQuit <- struct{}{}
	a.wildcardMatchesQuit <- struct{}{}
	a.getCIDRQuit <- struct{}{}
	a.reverseDNSFilterQuit <- struct{}{}

	for i := 0; i < numberofProcessingRoutines; i++ {
		<-a.done
	}
}

// NewUniqueElements - Removes elements that have duplicates in the original or new elements
func NewUniqueElements(orig []string, add ...string) []string {
	var n []string

	for _, av := range add {
		found := false
		s := strings.ToLower(av)

		// Check the original slice for duplicates
		for _, ov := range orig {
			if s == strings.ToLower(ov) {
				found = true
				break
			}
		}
		// Check that we didn't already add it in
		if !found {
			for _, nv := range n {
				if s == nv {
					found = true
					break
				}
			}
		}
		// If no duplicates were found, add the entry in
		if !found {
			n = append(n, s)
		}
	}
	return n
}

// UniqueAppend - Behaves like the Go append, but does not add duplicate elements
func UniqueAppend(orig []string, add ...string) []string {
	return append(orig, NewUniqueElements(orig, add...)...)
}

func SubdomainRegex(domain string) *regexp.Regexp {
	// Change all the periods into literal periods for the regex
	d := strings.Replace(domain, ".", "[.]", -1)

	return regexp.MustCompile(SUBRE + d)
}
