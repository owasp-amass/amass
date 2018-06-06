// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultWordlistURL = "https://raw.githubusercontent.com/caffix/amass/master/wordlists/namelist.txt"
)

// AmassConfig - Passes along optional configurations
type AmassConfig struct {
	sync.Mutex

	Graph *Graph

	// The channel that will receive the results
	Output chan *AmassOutput

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

	// The services used during the enumeration
	scrape  AmassService
	dns     *DNSService
	data    AmassService
	archive AmassService
	alt     AmassService
	brute   AmassService
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

func (c *AmassConfig) IsDomainInScope(name string) bool {
	var discovered bool

	for _, d := range c.Domains() {
		if strings.HasSuffix(name, d) {
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

func CheckConfig(config *AmassConfig) error {
	if config.BruteForcing && len(config.Wordlist) == 0 {
		return errors.New("The configuration contains no word list for brute forcing")
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
		Frequency:       25 * time.Millisecond,
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
	if ac.BruteForcing && len(ac.Wordlist) == 0 {
		config.Wordlist = GetDefaultWordlist()
	} else {
		config.Wordlist = ac.Wordlist
	}
	// Check that the config values have been set appropriately
	if ac.Frequency > config.Frequency {
		config.Frequency = ac.Frequency
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
	config.Resolvers = ac.Resolvers
	config.Blacklist = ac.Blacklist
	config.Active = ac.Active
	config.Neo4jPath = ac.Neo4jPath
	return config
}

func GetDefaultWordlist() []string {
	var list []string
	var wordlist io.Reader

	page := GetWebPageWithDialContext(DialContext, defaultWordlistURL, nil)
	if page == "" {
		return list
	}
	wordlist = strings.NewReader(page)

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
