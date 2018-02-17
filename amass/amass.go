// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caffix/recon"
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

	// This regular expression + the base domain will match on all names and subdomains
	SUBRE = "(([a-zA-Z0-9]{1}|[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"
)

// Amass - Contains amass state information
type Amass struct {
	// Mutex that protects the structure from concurrent access
	mtx sync.Mutex

	// The channel to send names on for DNS resolution and other processing
	Names chan *Subdomain

	// The channel that will receive names that have been successfully resolved
	Resolved chan *Subdomain

	// The slice that contains words to use when generating names
	Wordlist []string

	// Sets the maximum number of DNS queries per minute
	Frequency time.Duration

	// Keeps track of which DNS server is currently being queried
	DNSServerIndex int

	// Should we use the quiet DNS service?
	QuietDNS bool

	// Holds all the pending DNS name resolutions
	DNSResolveQueue []*Subdomain

	// The cache of CIDR network blocks that have already been looked up
	cidrCache map[string]*CIDRData

	// Keeps track of DNS wildcards discovered
	wildcards map[string]*recon.DnsWildcard

	// Prevents duplicate reverse DNS lookups being performed
	rDNSFilter map[string]struct{}
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
		Names:      make(chan *Subdomain, defaultAmassChanSize),
		Resolved:   make(chan *Subdomain, defaultAmassChanSize),
		Wordlist:   config.Wordlist,
		Frequency:  config.Frequency,
		QuietDNS:   config.QuietDNS,
		cidrCache:  make(map[string]*CIDRData),
		wildcards:  make(map[string]*recon.DnsWildcard),
		rDNSFilter: make(map[string]struct{}),
	}
	// Do not perform reverse lookups on localhost
	a.rDNSFilter["127.0.0.1"] = struct{}{}
	// Start the go-routine that will process DNS queries at the frequency
	go a.processDNSRequests()
	return a
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
