// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/internal/dns"
	"github.com/OWASP/Amass/amass/internal/utils"
)

const (
	defaultWordlistURL = "https://raw.githubusercontent.com/OWASP/Amass/master/wordlists/namelist.txt"
)

// AmassConfig - Passes along optional configurations
type AmassConfig struct {
	sync.Mutex

	Graph *Graph

	// The channel that will receive the results
	Output chan *AmassOutput

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

	// Use web archive data sources, which causes the enumeration to take longer
	UseWebArchives bool

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

func (c *AmassConfig) AddDomain(domain string) {
	c.Lock()
	defer c.Unlock()

	c.domains = utils.UniqueAppend(c.domains, domain)

	if _, found := c.regexps[domain]; !found {
		c.regexps[domain] = utils.SubdomainRegex(domain)
	}
}

func (c *AmassConfig) DomainRegex(domain string) *regexp.Regexp {
	c.Lock()
	defer c.Unlock()

	if re, found := c.regexps[domain]; found {
		return re
	}
	return nil
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

func CheckConfig(config *AmassConfig) error {
	if config.Output == nil {
		return errors.New("The configuration did not have an output channel")
	}

	if config.NoDNS && config.BruteForcing {
		return errors.New("Brute forcing cannot be performed without DNS resolution")
	}

	if config.NoDNS && config.Active {
		return errors.New("Active enumeration cannot be performed without DNS resolution")
	}

	if config.BruteForcing && len(config.Wordlist) == 0 {
		return errors.New("The configuration contains no word list for brute forcing")
	}

	if config.Frequency < DefaultConfig().Frequency {
		return errors.New("The configuration contains a invalid frequency")
	}

	if config.NoDNS && config.Neo4jPath != "" {
		return errors.New("Data cannot be provided to Neo4j without DNS resolution")
	}
	return nil
}

// DefaultConfig returns a config with values that have been tested
func DefaultConfig() *AmassConfig {
	config := &AmassConfig{
		Log:             log.New(ioutil.Discard, "", 0),
		Ports:           []int{80, 443},
		Recursive:       true,
		Alterations:     true,
		Frequency:       10 * time.Millisecond,
		MinForRecursive: 1,
		regexps:         make(map[string]*regexp.Regexp),
	}
	return config
}

// Ensures that all configuration elements have valid values
func CustomConfig(ac *AmassConfig) *AmassConfig {
	var err error
	config := DefaultConfig()

	for _, domain := range ac.Domains() {
		config.AddDomain(domain)
	}
	if len(config.Resolvers) > 0 {
		dns.SetCustomResolvers(config.Resolvers)
	}
	if ac.Log != nil {
		config.Log = ac.Log
	}
	if len(ac.Ports) > 0 {
		config.Ports = ac.Ports
	}
	if ac.BruteForcing && len(ac.Wordlist) == 0 {
		if config.Wordlist, err = GetDefaultWordlist(); err != nil {
			config.Log.Printf("Configuration error: %v", err)
			return nil
		}
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
	config.Whois = ac.Whois
	config.BruteForcing = ac.BruteForcing
	config.Recursive = ac.Recursive
	config.Alterations = ac.Alterations
	config.NoDNS = ac.NoDNS
	config.Output = ac.Output
	config.Resolvers = ac.Resolvers
	config.Blacklist = ac.Blacklist
	config.Active = ac.Active
	config.Neo4jPath = ac.Neo4jPath
	return config
}

func GetDefaultWordlist() ([]string, error) {
	var list []string
	var wordlist io.Reader

	page, err := utils.GetWebPage(defaultWordlistURL, nil)
	if err != nil {
		return list, err
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
	return list, nil
}
