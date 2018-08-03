// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

import (
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// AmassConfig - Passes along optional configurations
type AmassConfig struct {
	sync.Mutex

	// Logger for error messages
	Log *log.Logger

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
	NoDNS bool

	// Determines if active information gathering techniques will be used
	Active bool

	// A blacklist of subdomain names that will not be investigated
	Blacklist []string

	// Sets the maximum number of DNS queries per minute
	Frequency time.Duration

	// Preferred DNS resolvers identified by the user
	Resolvers []string

	// The Neo4j URL used by the bolt driver to connect with the database
	Neo4jPath string

	// The root domain names that the enumeration will target
	domains []string

	// The regular expressions for the root domains added to the enumeration
	regexps map[string]*regexp.Regexp
}

func (c *AmassConfig) DomainRegex(domain string) *regexp.Regexp {
	c.Lock()
	defer c.Unlock()

	if re, found := c.regexps[domain]; found {
		return re
	}
	return nil
}

func (c *AmassConfig) AddDomain(domain string) {
	c.domains = utils.UniqueAppend(c.domains, domain)

	if c.regexps == nil {
		c.regexps = make(map[string]*regexp.Regexp)
	}

	c.regexps[domain] = utils.SubdomainRegex(domain)
}

func (c *AmassConfig) Domains() []string {
	c.Lock()
	defer c.Unlock()

	return c.domains
}

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
