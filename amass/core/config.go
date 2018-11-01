// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

import (
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/OWASP/Amass/amass/utils"
)

// AmassConfig passes along optional Amass enumeration configurations
type AmassConfig struct {
	sync.Mutex

	// Logger for error messages
	Log *log.Logger

	// MaxFlow is a Semaphore that restricts the number of names moving through the architecture
	MaxFlow *utils.Semaphore

	// The ASNs that the enumeration will target
	ASNs []int

	// The CIDRs that the enumeration will target
	CIDRs []*net.IPNet

	// The IPs that the enumeration will target
	IPs []net.IP

	// The ports that will be checked for certificates
	Ports []int

	// Will whois info be used to add additional domains?
	Whois bool

	// The list of words to use when generating names
	Wordlist []string

	// Will the enumeration including brute forcing techniques
	BruteForcing bool

	// Will recursive brute forcing be performed?
	Recursive bool

	// Minimum number of subdomain discoveries before performing recursive brute forcing
	MinForRecursive int

	// Will discovered subdomain name alterations be generated?
	Alterations bool

	// Only access the data sources for names and return results?
	Passive bool

	// Determines if zone transfers will be attempted
	Active bool

	// A blacklist of subdomain names that will not be investigated
	Blacklist []string

	// The writer used to save the data operations performed
	DataOptsWriter io.Writer

	graph *Graph

	// The root domain names that the enumeration will target
	domains []string

	// The regular expressions for the root domains added to the enumeration
	regexps map[string]*regexp.Regexp
}

// Graph returns the Amass graph that contains all enumeration findings.
func (c *AmassConfig) Graph() *Graph {
	c.Lock()
	defer c.Unlock()

	return c.graph
}

// SetGraph assigns a Graph to the current configuration.
func (c *AmassConfig) SetGraph(g *Graph) {
	c.Lock()
	defer c.Unlock()

	c.graph = g
}

// DomainRegex returns the Regexp object for the domain name identified by the parameter.
func (c *AmassConfig) DomainRegex(domain string) *regexp.Regexp {
	c.Lock()
	defer c.Unlock()

	if re, found := c.regexps[domain]; found {
		return re
	}
	return nil
}

// AddDomain appends the domain name provided in the parameter to the list in the configuration.
func (c *AmassConfig) AddDomain(domain string) {
	c.domains = utils.UniqueAppend(c.domains, domain)

	if c.regexps == nil {
		c.regexps = make(map[string]*regexp.Regexp)
	}

	c.regexps[domain] = utils.SubdomainRegex(domain)
}

// Domains returns the list of domain names currently in the configuration.
func (c *AmassConfig) Domains() []string {
	c.Lock()
	defer c.Unlock()

	return c.domains
}

// IsDomainInScope returns true if the DNS name in the parameter ends with a domain in the config list.
func (c *AmassConfig) IsDomainInScope(name string) bool {
	var discovered bool

	for _, d := range c.Domains() {
		if name == d || strings.HasSuffix(name, "."+d) {
			discovered = true
			break
		}
	}
	return discovered
}

// WhichDomain returns the domain in the config list that the DNS name in the parameter end with.
func (c *AmassConfig) WhichDomain(name string) string {
	for _, d := range c.Domains() {
		if name == d || strings.HasSuffix(name, "."+d) {
			return d
		}
	}
	return ""
}

// Blacklisted returns true is the name in the parameter ends with a subdomain name in the config blacklist.
func (c *AmassConfig) Blacklisted(name string) bool {
	var resp bool

	for _, bl := range c.Blacklist {
		if match := strings.HasSuffix(name, bl); match {
			resp = true
			break
		}
	}
	return resp
}
