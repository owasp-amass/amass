// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"net"
	"regexp"
	"strings"

	"github.com/OWASP/Amass/v3/format"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/go-ini/ini"
)

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
	c.regexps[d] = dns.SubdomainRegex(d)
	if c.regexps[d] != nil {
		// Add the domain string to the list
		c.domains = append(c.domains, d)
	}

	c.domains = stringset.Deduplicate(c.domains)
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

// IsAddressInScope returns true if the addr parameter matches provided network scope and when
// no network scope has been set.
func (c *Config) IsAddressInScope(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}

	if len(c.Addresses) == 0 && len(c.CIDRs) == 0 {
		return true
	}

	for _, a := range c.Addresses {
		if a.String() == ip.String() {
			return true
		}
	}

	for _, cidr := range c.CIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
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

func (c *Config) loadScopeSettings(cfg *ini.File) error {
	scope, err := cfg.GetSection("scope")
	if err != nil {
		return nil
	}

	if scope.HasKey("address") {
		for _, addr := range scope.Key("address").ValueWithShadows() {
			var ips format.ParseIPs

			if err := ips.Set(addr); err != nil {
				return err
			}
			c.Addresses = append(c.Addresses, ips...)
		}
	}

	if scope.HasKey("cidr") {
		for _, cidr := range scope.Key("cidr").ValueWithShadows() {
			var ipnet *net.IPNet

			if _, ipnet, err = net.ParseCIDR(cidr); err != nil {
				return err
			}
			c.CIDRs = append(c.CIDRs, ipnet)
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
