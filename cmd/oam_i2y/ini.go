// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/caffix/stringset"
	"github.com/go-ini/ini"
	"github.com/owasp-amass/amass/v4/utils/net/dns"
)

// Updater allows an object to implement a method that updates a configuration.
type Updater interface {
	OverrideConfig(*Config) error
}

// Config passes along Amass configuration settings and options.
type Config struct {
	sync.Mutex

	// The graph databases used by the system / enumerations
	GraphDBs []*Database

	// The IP addresses specified as in scope
	Addresses []string

	// CIDR that is in scope
	CIDRs []string

	// ASNs specified as in scope
	ASNs []int

	// The ports that will be checked for certificates
	Ports []int

	// Will the enumeration including brute forcing techniques
	BruteForcing bool

	Bruteforcelist []string

	// Will recursive brute forcing be performed?
	Recursive bool

	// Will discovered subdomain name alterations be generated?
	Alterations bool

	Alterationslist []string

	// Only access the data sources for names and return results?
	Passive bool

	// Determines if zone transfers will be attempted
	Active bool

	// A blacklist of subdomain names that will not be investigated
	Blacklist []string

	// The minimum number of minutes that data source responses will be reused
	MinimumTTL int

	// Resolver settings
	Resolvers []string

	// The root domain names that the enumeration will target
	domains []string

	// The regular expressions for the root domains added to the enumeration
	regexps map[string]*regexp.Regexp

	// The data source configurations
	datasrcConfigs map[string]*DataSourceConfig
}

// DataSourceConfig contains the configurations specific to a data source.
type DataSourceConfig struct {
	Name  string
	TTL   int `ini:"ttl"`
	creds map[string]*Credentials
}

// Credentials contains values required for authenticating with web APIs.
type Credentials struct {
	Name     string
	Username string `ini:"username"`
	Password string `ini:"password"`
	Key      string `ini:"apikey"`
	Secret   string `ini:"secret"`
}

// Database contains values required for connecting with graph databases.
type Database struct {
	System   string
	Primary  bool   `ini:"primary"`
	URL      string `ini:"url"`
	Username string `ini:"username"`
	Password string `ini:"password"`
	DBName   string `ini:"database"`
	Options  string `ini:"options"`
}

// LoadSettings parses settings from an .ini file and assigns them to the Config.
func (c *Config) LoadSettings(path string) error {
	cfg, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:  true,
		AllowShadows: true,
	}, path)
	if err != nil {
		return fmt.Errorf("failed to load the configuration file: %v", err)
	}
	// Get the easy ones out of the way using mapping
	if err = cfg.MapTo(c); err != nil {
		return fmt.Errorf("error mapping configuration settings to internal values: %v", err)
	}
	// Attempt to load a special mode of operation specified by the user
	if cfg.Section(ini.DefaultSection).HasKey("mode") {
		mode := cfg.Section(ini.DefaultSection).Key("mode").String()

		if mode == "passive" {
			c.Passive = true
		} else if mode == "active" {
			c.Active = true
		}
	}

	loads := []func(cfg *ini.File) error{
		c.loadResolverSettings,
		c.loadScopeSettings,
		c.loadAlterationSettings,
		c.loadBruteForceSettings,
		c.loadDatabaseSettings,
		c.loadDataSourceSettings,
	}
	for _, load := range loads {
		if err := load(cfg); err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) loadDataSourceSettings(cfg *ini.File) error {
	sec, err := cfg.GetSection("data_sources")
	if err != nil {
		return err
	}

	if sec.HasKey("minimum_ttl") {
		if ttl, err := sec.Key("minimum_ttl").Int(); err == nil {
			c.MinimumTTL = ttl
		}
	}

	for _, child := range sec.ChildSections() {
		name := strings.Split(child.Name(), ".")[1]

		if name == "disabled" {
			continue
		}

		dsc := c.GetDataSourceConfig(name)
		// Parse the Database information and assign to the Config
		if err := child.MapTo(dsc); err != nil {
			continue
		}

		if c.MinimumTTL > dsc.TTL {
			dsc.TTL = c.MinimumTTL
		}
		// Check for data source credentials
		for _, cr := range child.ChildSections() {
			setName := strings.Split(cr.Name(), ".")[2]

			creds := &Credentials{Name: setName}
			if err := cr.MapTo(creds); err != nil {
				return err
			}
			if err := dsc.AddCredentials(creds); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Config) loadDatabaseSettings(cfg *ini.File) error {
	sec, err := cfg.GetSection("graphdbs")
	if err != nil {
		return nil
	}

	for _, child := range sec.ChildSections() {
		db := new(Database)
		name := strings.Split(child.Name(), ".")[1]

		// Parse the Database information and assign to the Config
		if err := child.MapTo(db); err == nil {
			db.System = name
			c.GraphDBs = append(c.GraphDBs, db)
		}
	}

	return nil
}

func (c *Config) loadResolverSettings(cfg *ini.File) error {
	sec, err := cfg.GetSection("resolvers")
	if err != nil {
		return nil
	}

	c.Resolvers = stringset.Deduplicate(sec.Key("resolver").ValueWithShadows())
	if len(c.Resolvers) == 0 {
		return errors.New("no resolver keys were found in the resolvers section")
	}

	return nil
}

func (c *Config) loadScopeSettings(cfg *ini.File) error {
	scope, err := cfg.GetSection("scope")
	if err != nil {
		return nil
	}

	if scope.HasKey("address") {
		c.Addresses = append(c.Addresses, scope.Key("address").ValueWithShadows()...)
	}

	if scope.HasKey("cidr") {
		for _, cidr := range scope.Key("cidr").ValueWithShadows() {
			// Verify the CIDR is valid
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return err
			}
			c.CIDRs = append(c.CIDRs, cidr)
		}
	}

	if scope.HasKey("asn") {
		for _, asn := range scope.Key("asn").ValueWithShadows() {
			c.ASNs = uniqueIntAppend(c.ASNs, asn)
		}
	}

	if scope.HasKey("port") {
		for _, port := range scope.Key("port").ValueWithShadows() {
			c.Ports = uniqueIntAppend(c.Ports, port)
		}
	}

	// Load up all the DNS domain names
	if domains, err := cfg.GetSection("scope.domains"); err == nil {
		for _, domain := range domains.Key("domain").ValueWithShadows() {
			c.AddDomain(domain)
		}
	}

	// Load up all the blacklisted subdomain names
	if blacklisted, err := cfg.GetSection("scope.blacklisted"); err == nil {
		c.Blacklist = stringset.Deduplicate(blacklisted.Key("subdomain").ValueWithShadows())
	}

	return nil
}

func (c *Config) loadBruteForceSettings(cfg *ini.File) error {
	bruteforce, err := cfg.GetSection("bruteforce")
	if err != nil {
		return nil
	}

	// get the list
	c.Bruteforcelist = bruteforce.Key("wordlist_file").ValueWithShadows()

	// get the options like the worldlist somehow
	c.BruteForcing = bruteforce.Key("enabled").MustBool(true)
	if !c.BruteForcing {
		return nil
	}
	return nil
}

func (c *Config) loadAlterationSettings(cfg *ini.File) error {
	alterations, err := cfg.GetSection("alterations")
	if err != nil {
		return nil
	}

	// get the list
	c.Alterationslist = alterations.Key("wordlist_file").ValueWithShadows()

	c.Alterations = alterations.Key("enabled").MustBool(true)
	if !c.Alterations {
		return nil
	}
	return nil
}

// GetDataSourceConfig returns the DataSourceConfig associated with the data source name argument.
func (c *Config) GetDataSourceConfig(source string) *DataSourceConfig {
	c.Lock()
	defer c.Unlock()

	key := strings.TrimSpace(source)
	if key == "" {
		return nil
	}
	if c.datasrcConfigs == nil {
		c.datasrcConfigs = make(map[string]*DataSourceConfig)
	}
	if _, found := c.datasrcConfigs[key]; !found {
		c.datasrcConfigs[key] = &DataSourceConfig{Name: key}
	}
	return c.datasrcConfigs[key]
}

// AddCredentials adds the Credentials provided to the configuration.
func (dsc *DataSourceConfig) AddCredentials(cred *Credentials) error {
	if cred == nil || cred.Name == "" {
		return fmt.Errorf("AddCredentials: The Credentials argument is invalid")
	}

	if dsc.creds == nil {
		dsc.creds = make(map[string]*Credentials)
	}

	dsc.creds[cred.Name] = cred
	return nil
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
	c.regexps[d] = dns.SubdomainRegex(d)
	if c.regexps[d] != nil {
		// Add the domain string to the list
		c.domains = append(c.domains, d)
	}

	c.domains = stringset.Deduplicate(c.domains)
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
