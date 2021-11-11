// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/dns"
	"github.com/caffix/stringset"
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
func (c *Config) AddDomains(domains ...string) {
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

	if domain := c.WhichDomain(name); domain != "" {
		discovered = true
	}

	return discovered
}

// WhichDomain returns the domain in the config list that the DNS name in the parameter ends with.
func (c *Config) WhichDomain(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))

	for _, d := range c.Domains() {
		if hasPathSuffix(n, d) {
			return d
		}
	}
	return ""
}

func hasPathSuffix(path, suffix string) bool {
	if strings.HasSuffix(path, suffix) {
		plen := len(path)
		slen := len(suffix)

		// Check for exact match first to guard against out of bound index
		if plen == slen || path[plen-slen-1] == '.' {
			return true
		}
	}
	return false
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

// BlacklistSubdomain adds a subdomain name to the config blacklist.
func (c *Config) BlacklistSubdomain(name string) {
	c.blacklistLock.Lock()
	defer c.blacklistLock.Unlock()

	set := stringset.New(c.Blacklist...)
	defer set.Close()
	set.Insert(strings.TrimSpace(name))

	c.Blacklist = set.Slice()
}

// Blacklisted returns true is the name in the parameter ends with a subdomain name in the config blacklist.
func (c *Config) Blacklisted(name string) bool {
	c.blacklistLock.Lock()
	defer c.blacklistLock.Unlock()

	n := strings.ToLower(strings.TrimSpace(name))

	for _, bl := range c.Blacklist {
		if hasPathSuffix(n, bl) {
			return true
		}
	}

	return false
}

func (c *Config) loadScopeSettings(cfg *ini.File) error {
	scope, err := cfg.GetSection("scope")
	if err != nil {
		return nil
	}

	if scope.HasKey("address") {
		for _, addr := range scope.Key("address").ValueWithShadows() {
			var ips parseIPs

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

type parseIPs []net.IP

func (p *parseIPs) String() string {
	if p == nil {
		return ""
	}

	var ipaddrs []string
	for _, ipaddr := range *p {
		ipaddrs = append(ipaddrs, ipaddr.String())
	}
	return strings.Join(ipaddrs, ",")
}

// Set implements the flag.Value interface.
func (p *parseIPs) Set(s string) error {
	if s == "" {
		return fmt.Errorf("IP address parsing failed")
	}

	ips := strings.Split(s, ",")
	for _, ip := range ips {
		// Is this an IP range?
		err := p.parseRange(ip)
		if err == nil {
			continue
		}
		addr := net.ParseIP(ip)
		if addr == nil {
			return fmt.Errorf("%s is not a valid IP address or range", ip)
		}
		*p = append(*p, addr)
	}
	return nil
}

func (p *parseIPs) appendIPs(addrs []net.IP) error {
	for _, addr := range addrs {
		*p = append(*p, addr)
	}
	return nil
}

func (p *parseIPs) parseRange(s string) error {
	twoIPs := strings.Split(s, "-")

	if twoIPs[0] == s {
		return fmt.Errorf("%s is not a valid IP range", s)
	}
	start := net.ParseIP(twoIPs[0])
	end := net.ParseIP(twoIPs[1])
	if end == nil {
		num, err := strconv.Atoi(twoIPs[1])
		if err == nil {
			end = net.ParseIP(twoIPs[0])
			end[len(end)-1] = byte(num)
		}
	}
	if start == nil || end == nil {
		return fmt.Errorf("%s is not a valid IP range", s)
	}

	ips := amassnet.RangeHosts(start, end)
	if len(ips) == 0 {
		return fmt.Errorf("%s is not a valid IP range", s)
	}
	return p.appendIPs(ips)
}
