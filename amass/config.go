// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gamexg/proxyclient"
)

// AmassConfig - Passes along optional configurations
type AmassConfig struct {
	sync.Mutex

	// The channel that will receive the results
	Output chan *AmassRequest

	// The ASNs that the enumeration will target
	ASNs []int

	// The CIDRs that the enumeration will target
	CIDRs []*net.IPNet

	// The IPs that the enumeration will target
	IPs []net.IP

	// The ports that will be checked for certificates
	Ports []int

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

	// A blacklist of subdomain names that will not be investigated
	Blacklist []string

	// Sets the maximum number of DNS queries per minute
	Frequency time.Duration

	// Preferred DNS resolvers identified by the user
	Resolvers []string

	// Indicate that Amass cannot add domains to the config
	AdditionalDomains bool

	// The root domain names that the enumeration will target
	domains []string

	// Is responsible for performing simple DNS resolutions
	dns *queries

	// Handles selecting the next DNS resolver to be used
	resolver *resolvers

	// Performs lookups of root domain names from subdomain names
	domainLookup *DomainLookup

	// Detects DNS wildcards
	wildcards *Wildcards

	// The optional proxy connection for the enumeration to use
	proxy proxyclient.ProxyClient
}

func (c *AmassConfig) Setup() {
	// Setup the services potentially needed by all of amass
	c.dns = newQueriesSubsystem(c)
	c.domainLookup = NewDomainLookup(c)
	c.wildcards = NewWildcardDetection(c)
	c.resolver = newResolversSubsystem(c)
}

func (c *AmassConfig) AddDomains(names []string) {
	c.Lock()
	defer c.Unlock()

	c.domains = UniqueAppend(c.domains, names...)
}

func (c *AmassConfig) Domains() []string {
	c.Lock()
	defer c.Unlock()

	return c.domains
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

func CheckConfig(config *AmassConfig) error {
	if len(config.Wordlist) == 0 {
		return errors.New("The configuration contains no wordlist")
	}

	if config.Frequency < DefaultConfig().Frequency {
		return errors.New("The configuration contains a invalid frequency")
	}

	if config.Output == nil {
		return errors.New("The configuration did not have an output channel")
	}
	return nil
}

// DefaultConfig returns a config with values that have been tested
func DefaultConfig() *AmassConfig {
	config := &AmassConfig{
		Ports:           []int{443},
		Recursive:       true,
		Alterations:     true,
		Frequency:       50 * time.Millisecond,
		MinForRecursive: 1,
	}
	return config
}

// Ensures that all configuration elements have valid values
func CustomConfig(ac *AmassConfig) *AmassConfig {
	config := DefaultConfig()

	if len(ac.Domains()) > 0 {
		config.AddDomains(ac.Domains())
	}
	if len(ac.Ports) > 0 {
		config.Ports = ac.Ports
	}
	if len(ac.Wordlist) == 0 {
		config.Wordlist = GetDefaultWordlist()
	} else {
		config.Wordlist = ac.Wordlist
	}
	// Check that the config values have been set appropriately
	if ac.Frequency > config.Frequency {
		config.Frequency = ac.Frequency
	}
	if ac.proxy != nil {
		config.proxy = ac.proxy
	}
	if ac.MinForRecursive > config.MinForRecursive {
		config.MinForRecursive = ac.MinForRecursive
	}
	config.ASNs = ac.ASNs
	config.CIDRs = ac.CIDRs
	config.IPs = ac.IPs
	config.BruteForcing = ac.BruteForcing
	config.Recursive = ac.Recursive
	config.Alterations = ac.Alterations
	config.Output = ac.Output
	config.AdditionalDomains = ac.AdditionalDomains
	config.Resolvers = ac.Resolvers
	config.Blacklist = ac.Blacklist
	config.Setup()
	return config
}

func GetDefaultWordlist() []string {
	var list []string
	var wordlist io.Reader

	resp, err := http.Get(defaultWordlistURL)
	if err != nil {
		return list
	}
	defer resp.Body.Close()
	wordlist = resp.Body

	scanner := bufio.NewScanner(wordlist)
	// Once we have used all the words, we are finished
	for scanner.Scan() {
		// Get the next word in the list
		word := scanner.Text()
		if word != "" {
			// Add the word to the list
			list = append(list, word)
		}
	}
	return list
}

//--------------------------------------------------------------------------------------------------
// ReverseWhois - Returns domain names that are related to the domain provided
func (c *AmassConfig) ReverseWhois(domain string) []string {
	var domains []string

	page := GetWebPageWithDialContext(c.DialContext,
		"http://viewdns.info/reversewhois/?q="+domain)
	if page == "" {
		return []string{}
	}
	// Pull the table we need from the page content
	table := getViewDNSTable(page)
	// Get the list of domain names discovered through
	// the reverse DNS service
	re := regexp.MustCompile("<tr><td>([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1}[.]{1}[a-zA-Z0-9-]+)</td><td>")
	subs := re.FindAllStringSubmatch(table, -1)
	for _, match := range subs {
		sub := match[1]
		if sub == "" {
			continue
		}
		domains = append(domains, strings.TrimSpace(sub))
	}
	sort.Strings(domains)
	return domains
}

func getViewDNSTable(page string) string {
	var begin, end int
	s := page

	for i := 0; i < 4; i++ {
		b := strings.Index(s, "<table")
		if b == -1 {
			return ""
		}
		begin += b + 6

		if e := strings.Index(s[b:], "</table>"); e == -1 {
			return ""
		} else {
			end = begin + e
		}

		s = page[end+8:]
	}

	i := strings.Index(page[begin:end], "<table")
	i = strings.Index(page[begin+i+6:end], "<table")
	return page[begin+i : end]
}

//--------------------------------------------------------------------------------------------------
// Methods that handle networking that is specific to the Amass configuration

func (c *AmassConfig) SetupProxyConnection(addr string) error {
	client, err := proxyclient.NewProxyClient(addr)
	if err == nil {
		c.proxy = client
		// Override the Go default DNS resolver to prevent leakage
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial:     c.DNSDialContext,
		}
	}
	return err
}

func (c *AmassConfig) DNSDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	resolver := c.resolver.Next()

	if c.proxy != nil {
		if timeout, ok := ctx.Deadline(); ok {
			return c.proxy.DialTimeout(network, resolver, timeout.Sub(time.Now()))
		}
		return c.proxy.Dial(network, resolver)
	}

	d := &net.Dialer{}
	return d.DialContext(ctx, network, resolver)
}

func (c *AmassConfig) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.proxy != nil {
		if timeout, ok := ctx.Deadline(); ok {
			return c.proxy.DialTimeout(network, address, timeout.Sub(time.Now()))
		}
		return c.proxy.Dial(network, address)
	}

	d := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     c.DNSDialContext,
		},
	}
	return d.DialContext(ctx, network, address)
}
