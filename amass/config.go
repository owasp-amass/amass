// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"context"
	"errors"
	//"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gamexg/proxyclient"
)

// AmassConfig - Passes along optional configurations
type AmassConfig struct {
	sync.Mutex

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

	// Will discovered subdomain name alterations be generated?
	Alterations bool

	// Sets the maximum number of DNS queries per minute
	Frequency time.Duration

	// The channel that will receive the results
	Output chan *AmassRequest

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
		Ports:       []int{443},
		Recursive:   true,
		Alterations: true,
		Frequency:   50 * time.Millisecond,
	}
	return config
}

// Ensures that all configuration elements have valid values
func CustomConfig(ac *AmassConfig) *AmassConfig {
	config := DefaultConfig()

	if len(ac.Domains()) > 0 {
		config.AddDomains(ac.Domains())
	}

	config.ASNs = ac.ASNs
	config.CIDRs = ac.CIDRs
	config.IPs = ac.IPs

	if len(ac.Ports) > 0 {
		config.Ports = ac.Ports
	}

	if len(ac.Wordlist) == 0 {
		config.Wordlist = GetDefaultWordlist()
	} else {
		config.Wordlist = ac.Wordlist
	}

	config.BruteForcing = ac.BruteForcing
	config.Recursive = ac.Recursive

	// Check that the config values have been set appropriately
	if ac.Frequency > config.Frequency {
		config.Frequency = ac.Frequency
	}

	if ac.proxy != nil {
		config.proxy = ac.proxy
	}

	config.Output = ac.Output
	config.AdditionalDomains = ac.AdditionalDomains
	config.Resolvers = ac.Resolvers
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
