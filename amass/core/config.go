// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/OWASP/Amass/amass/utils"
	"github.com/go-ini/ini"
	"github.com/google/uuid"
)

const (
	defaultWordlistURL    = "https://raw.githubusercontent.com/OWASP/Amass/master/wordlists/namelist.txt"
	defaultAltWordlistURL = "https://raw.githubusercontent.com/OWASP/Amass/master/wordlists/alterations.txt"
)

// Config passes along Amass enumeration configurations
type Config struct {
	sync.Mutex

	// A Universally Unique Identifier (UUID) for the enumeration
	UUID uuid.UUID

	// Logger for error messages
	Log *log.Logger

	// The writer used to save the data operations performed
	DataOptsWriter io.Writer

	// The directory that stores the bolt db and other files created
	Dir string `ini:"output_directory"`

	// The settings for connecting with a Gremlin Server
	GremlinURL  string
	GremlinUser string
	GremlinPass string

	// The maximum number of concurrent DNS queries
	MaxDNSQueries int `ini:"maximum_dns_queries"`

	// Semaphore to enforce the maximum DNS queries
	SemMaxDNSQueries utils.Semaphore

	// The IP addresses specified as in scope
	Addresses []net.IP

	// CIDR that is in scope
	CIDRs []*net.IPNet

	// ASNs specified as in scope
	ASNs []int

	// The ports that will be checked for certificates
	Ports []int

	// The list of words to use when generating names
	Wordlist []string

	// Will the enumeration including brute forcing techniques
	BruteForcing bool `ini:"brute_forcing"`

	// Will recursive brute forcing be performed?
	Recursive bool `ini:"recursive_brute_forcing"`

	// Minimum number of subdomain discoveries before performing recursive brute forcing
	MinForRecursive int `ini:"minimum_for_recursive"`

	// Will discovered subdomain name alterations be generated?
	Alterations    bool
	FlipWords      bool
	FlipNumbers    bool
	AddWords       bool
	AddNumbers     bool
	MinForWordFlip int
	EditDistance   int
	AltWordlist    []string

	// Only access the data sources for names and return results?
	Passive bool

	// Determines if zone transfers will be attempted
	Active bool

	// Determines if unresolved DNS names will be output by the enumeration
	IncludeUnresolvable bool `ini:"include_unresolvable"`

	// A blacklist of subdomain names that will not be investigated
	Blacklist []string

	// A list of data sources that should not be utilized
	DisabledDataSources []string

	// The root domain names that the enumeration will target
	domains []string

	// The regular expressions for the root domains added to the enumeration
	regexps map[string]*regexp.Regexp

	// The API keys used by various data sources
	apikeys map[string]*APIKey
}

// APIKey contains values required for authenticating with web APIs.
type APIKey struct {
	Username string `ini:"username"`
	Password string `ini:"password"`
	Key      string `ini:"apikey"`
	Secret   string `ini:"secret"`
}

// CheckSettings runs some sanity checks on the configuration options selected.
func (c *Config) CheckSettings() error {
	var err error

	if c.BruteForcing {
		if c.Passive {
			return errors.New("Brute forcing cannot be performed without DNS resolution")
		} else if len(c.Wordlist) == 0 {
			c.Wordlist, err = getWordlistByURL(defaultWordlistURL)
		}
	}
	if c.Passive && c.Active {
		return errors.New("Active enumeration cannot be performed without DNS resolution")
	}
	if c.MaxDNSQueries <= 0 {
		c.MaxDNSQueries = 1000
	}
	if len(c.Ports) == 0 {
		c.Ports = []int{443}
	}
	if c.Alterations {
		if len(c.AltWordlist) == 0 {
			c.AltWordlist, err = getWordlistByURL(defaultAltWordlistURL)
		}
	}
	c.SemMaxDNSQueries = utils.NewSimpleSemaphore(c.MaxDNSQueries)
	return err
}

// DomainRegex returns the Regexp object for the domain name identified by the parameter.
func (c *Config) DomainRegex(domain string) *regexp.Regexp {
	c.Lock()
	defer c.Unlock()

	if re, found := c.regexps[domain]; found {
		return re
	}
	return nil
}

// AddDomains appends the domain names provided in the parameter to the list in the configuration.
func (c *Config) AddDomains(domains []string) {
	for _, d := range domains {
		c.AddDomain(d)
	}
}

// AddDomain appends the domain name provided in the parameter to the list in the configuration.
func (c *Config) AddDomain(domain string) {
	c.Lock()
	defer c.Unlock()

	// Check that the domain string is not empty
	d := strings.TrimSpace(domain)
	if d == "" {
		return
	}
	// Check that it is a domain with at least two labels
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return
	}
	// Check that none of the labels are empty
	for _, label := range labels {
		if label == "" {
			return
		}
	}
	// Check that the regular expression map has been initialized
	if c.regexps == nil {
		c.regexps = make(map[string]*regexp.Regexp)
	}
	// Create the regular expression for this domain
	c.regexps[d] = utils.SubdomainRegex(d)
	if c.regexps[d] != nil {
		// Add the domain string to the list
		c.domains = utils.UniqueAppend(c.domains, d)
	}
}

// Domains returns the list of domain names currently in the configuration.
func (c *Config) Domains() []string {
	c.Lock()
	defer c.Unlock()

	return c.domains
}

// IsDomainInScope returns true if the DNS name in the parameter ends with a domain in the config list.
func (c *Config) IsDomainInScope(name string) bool {
	var discovered bool

	n := strings.ToLower(strings.TrimSpace(name))
	for _, d := range c.Domains() {
		if n == d || strings.HasSuffix(n, "."+d) {
			discovered = true
			break
		}
	}
	return discovered
}

// WhichDomain returns the domain in the config list that the DNS name in the parameter ends with.
func (c *Config) WhichDomain(name string) string {
	n := strings.TrimSpace(name)

	for _, d := range c.Domains() {
		if n == d || strings.HasSuffix(n, "."+d) {
			return d
		}
	}
	return ""
}

// Blacklisted returns true is the name in the parameter ends with a subdomain name in the config blacklist.
func (c *Config) Blacklisted(name string) bool {
	var resp bool

	n := strings.TrimSpace(name)
	for _, bl := range c.Blacklist {
		if match := strings.HasSuffix(n, bl); match {
			resp = true
			break
		}
	}
	return resp
}

// ExcludeDisabledDataSources returns a list of data sources excluding DisabledDataSources.
func (c *Config) ExcludeDisabledDataSources(services []Service) []Service {
	var enabled []Service

	for _, s := range services {
		include := true

		for _, disabled := range c.DisabledDataSources {
			if strings.EqualFold(disabled, s.String()) {
				include = false
				break
			}
		}
		if include {
			enabled = append(enabled, s)
		}
	}
	return enabled
}

// AddAPIKey adds the data source and API key association provided to the configuration.
func (c *Config) AddAPIKey(source string, ak *APIKey) {
	c.Lock()
	defer c.Unlock()

	idx := strings.TrimSpace(source)
	if idx == "" {
		return
	}

	if c.apikeys == nil {
		c.apikeys = make(map[string]*APIKey)
	}
	c.apikeys[strings.ToLower(idx)] = ak
}

// GetAPIKey returns the API key associated with the provided data source name.
func (c *Config) GetAPIKey(source string) *APIKey {
	c.Lock()
	defer c.Unlock()

	idx := strings.TrimSpace(source)
	if apikey, found := c.apikeys[strings.ToLower(idx)]; found {
		return apikey
	}
	return nil
}

func (c *Config) loadNetworkSettings(cfg *ini.File) error {
	if network, err := cfg.GetSection("network_settings"); err == nil {
		for _, addr := range network.Key("address").ValueWithShadows() {
			var ips utils.ParseIPs

			if err := ips.Set(addr); err != nil {
				return err
			}
			c.Addresses = append(c.Addresses, ips...)
		}

		for _, cidr := range network.Key("cidr").ValueWithShadows() {
			var ipnet *net.IPNet

			if _, ipnet, err = net.ParseCIDR(cidr); err != nil {
				return err
			}
			c.CIDRs = append(c.CIDRs, ipnet)
		}

		for _, asn := range network.Key("asn").ValueWithShadows() {
			c.ASNs = uniqueIntAppend(c.ASNs, asn)
		}

		for _, port := range network.Key("port").ValueWithShadows() {
			c.Ports = uniqueIntAppend(c.Ports, port)
		}
	}
	return nil
}

func (c *Config) loadBruteForceSettings(cfg *ini.File) error {
	if bruteforce, err := cfg.GetSection("bruteforce"); err == nil {
		c.BruteForcing = bruteforce.Key("enabled").MustBool(true)

		if c.BruteForcing {
			c.Recursive = bruteforce.Key("recursive").MustBool(true)
			c.MinForRecursive = bruteforce.Key("minimum_for_recursive").MustInt(0)
			if bruteforce.HasKey("wordlist_file") {
				for _, wordlist := range bruteforce.Key("wordlist_file").ValueWithShadows() {
					list, err := GetListFromFile(wordlist)
					if err != nil {
						return fmt.Errorf("Unable to load the file in the bruteforce wordlist_file setting: %s: %v", wordlist, err)
					}
					c.Wordlist = utils.UniqueAppend(c.Wordlist, list...)
				}
			}
		}
	}
	return nil
}

func (c *Config) loadAlterationSettings(cfg *ini.File) error {
	if alterations, err := cfg.GetSection("alterations"); err == nil {
		c.Alterations = alterations.Key("enabled").MustBool(true)

		if c.Alterations {
			c.FlipWords = alterations.Key("flip_words").MustBool(true)
			c.AddWords = alterations.Key("add_words").MustBool(true)
			c.FlipNumbers = alterations.Key("flip_numbers").MustBool(true)
			c.AddNumbers = alterations.Key("add_numbers").MustBool(true)
			c.MinForWordFlip = alterations.Key("minimum_for_word_flip").MustInt(2)
			c.EditDistance = alterations.Key("edit_distance").MustInt(1)
			if alterations.HasKey("wordlist_file") {
				for _, wordlist := range alterations.Key("wordlist_file").ValueWithShadows() {
					list, err := GetListFromFile(wordlist)
					if err != nil {
						return fmt.Errorf("Unable to load the file in the alterations wordlist_file setting: %s: %v", wordlist, err)
					}
					c.AltWordlist = utils.UniqueAppend(c.AltWordlist, list...)
				}
			}
		}
	}
	return nil
}

// LoadSettings parses settings from an .ini file and assigns them to the Config.
func (c *Config) LoadSettings(path string) error {
	cfg, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:  true,
		AllowShadows: true,
	}, path)
	if err != nil {
		return fmt.Errorf("Failed to load the configuration file: %v", err)
	}
	// Get the easy ones out of the way using mapping
	if err = cfg.MapTo(c); err != nil {
		return fmt.Errorf("Error mapping configuration settings to internal values: %v", err)
	}
	// Attempt to load a special mode of operation specified by the user
	if cfg.Section(ini.DEFAULT_SECTION).HasKey("mode") {
		mode := cfg.Section(ini.DEFAULT_SECTION).Key("mode").String()

		if mode == "passive" {
			c.Passive = true
		} else if mode == "active" {
			c.Active = true
		}
	}
	// Load up all the DNS domain names
	if domains, err := cfg.GetSection("domains"); err == nil {
		for _, domain := range domains.Key("domain").ValueWithShadows() {
			c.AddDomain(domain)
		}
	}
	// Load up all the blacklisted subdomain names
	if blacklisted, err := cfg.GetSection("blacklisted"); err == nil {
		c.Blacklist = utils.UniqueAppend(c.Blacklist,
			blacklisted.Key("subdomain").ValueWithShadows()...)
	}
	// Load up all the disabled data source names
	if disabled, err := cfg.GetSection("disabled_data_sources"); err == nil {
		c.DisabledDataSources = utils.UniqueAppend(
			c.DisabledDataSources, disabled.Key("data_source").ValueWithShadows()...)
	}
	// Load up all the Gremlin Server settings
	if gremlin, err := cfg.GetSection("gremlin"); err == nil {
		c.GremlinURL = gremlin.Key("url").String()
		c.GremlinUser = gremlin.Key("username").String()
		c.GremlinPass = gremlin.Key("password").String()
	}

	if err := c.loadNetworkSettings(cfg); err != nil {
		return err
	}

	if err := c.loadAlterationSettings(cfg); err != nil {
		return err
	}

	if err := c.loadBruteForceSettings(cfg); err != nil {
		return err
	}

	// Load up all API key information from data source sections
	nonAPISections := []string{
		"alterations",
		"bruteforce",
		"default",
		"domains",
		"resolvers",
		"blacklisted",
		"disabled_data_sources",
		"gremlin",
	}
outer:
	for _, section := range cfg.Sections() {
		name := section.Name()
		// Skip sections that are not related to data sources
		for _, doneSection := range nonAPISections {
			if name == doneSection {
				continue outer
			}
		}

		key := new(APIKey)
		// Parse the API key information and assign to the Config
		if err := section.MapTo(key); err == nil {
			c.AddAPIKey(name, key)
		}
	}
	return nil
}

// GetResolversFromSettings loads the configuration file and returns all resolvers found.
func GetResolversFromSettings(path string) ([]string, error) {
	cfg, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:  true,
		AllowShadows: true,
	}, path)
	if err != nil {
		return nil, fmt.Errorf("Failed to load the configuration file: %v", err)
	}
	// Check that the resolvers section exists in the config file
	sec, err := cfg.GetSection("resolvers")
	if err != nil {
		return nil, fmt.Errorf("The config file does not contain a resolvers section: %v", err)
	}

	resolvers := sec.Key("resolver").ValueWithShadows()
	if len(resolvers) == 0 {
		return nil, errors.New("No resolver keys were found in the resolvers section")
	}
	return resolvers, nil
}

// GetListFromFile reads a wordlist text or gzip file
// and returns the slice of words
func GetListFromFile(path string) ([]string, error) {
	var reader io.Reader

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("Error opening the file %s: %v", path, err)
	}
	defer file.Close()
	reader = file

	// We need to determine if this is a gzipped file or a plain text file, so we
	// first read the first 512 bytes to pass them down to http.DetectContentType
	// for mime detection. The file is rewinded before passing it along to the
	// next reader
	head := make([]byte, 512)
	if _, err = file.Read(head); err != nil {
		return nil, fmt.Errorf("Error reading the first 512 bytes from %s: %s", path, err)
	}
	if _, err = file.Seek(0, 0); err != nil {
		return nil, fmt.Errorf("Error rewinding the file %s: %s", path, err)
	}

	// Read the file as gzip if it's actually compressed
	if mt := http.DetectContentType(head); mt == "application/gzip" || mt == "application/x-gzip" {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("Error gz-reading the file %s: %v", path, err)
		}
		defer gzReader.Close()
		reader = gzReader
	}
	return getWordList(reader)
}

func getWordlistByURL(url string) ([]string, error) {
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain the wordlist at %s: %v", url, err)
	}
	return getWordList(strings.NewReader(page))
}

func getWordList(reader io.Reader) ([]string, error) {
	var words []string

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// Get the next word in the list
		w := strings.TrimSpace(scanner.Text())
		if err := scanner.Err(); err == nil && w != "" {
			words = append(words, w)
		}
	}
	return words, nil
}

func uniqueIntAppend(s []int, e string) []int {
	if a1, err := strconv.Atoi(e); err == nil {
		var found bool

		for _, a2 := range s {
			if a1 == a2 {
				found = true
				break
			}
		}
		if !found {
			s = append(s, a1)
		}
	}
	return s
}
