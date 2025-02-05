// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/caffix/stringset"
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	"github.com/owasp-amass/amass/v4/utils/net/dns"
)

func (c *Config) loadSeedandScopeSettings() error {
	if c.Seed == nil || c.Seed.isScopeEmpty(false) {
		if c.Scope == nil {
			return fmt.Errorf("config seed and scope are not initialized")
		} else {
			if err := c.Scope.populate(); err != nil {
				return err
			}
			c.Seed = c.Scope
			return nil
		}
	} else if err := c.Seed.populate(); err != nil {
		return err
	}

	if c.Scope == nil || !c.Scope.isScopeEmpty(true) {
		if err := c.Seed.populate(); err != nil {
			return err
		}
		c.Scope = c.Seed
		c.Scope.Ports = []int{80, 443}
		return nil
	} else if err := c.Scope.populate(); err != nil {
		return err
	}

	return nil
}

func (s *Scope) isScopeEmpty(scopeSwitch bool) bool {
	isEmpty := true

	if len(s.Domains) > 0 {
		isEmpty = false
	}
	if len(s.Addresses) > 0 {
		isEmpty = false
	}
	if len(s.CIDRs) > 0 {
		isEmpty = false
	}
	if len(s.ASNs) > 0 {
		isEmpty = false
	}
	if len(s.IP) > 0 {
		isEmpty = false
	}
	if scopeSwitch && portCheck(s.Ports) {
		isEmpty = false
	} else if len(s.Ports) > 0 {
		isEmpty = false
	}
	if len(s.Blacklist) > 0 {
		isEmpty = false
	}

	return isEmpty
}

func (s *Scope) populate() error {
	// Convert string CIDRs to net.IP and net.IPNet
	s.CIDRs = s.toCIDRs(s.CIDRStrings)

	// Convert PortsRaw to Ports
	if err := s.parsePorts(); err != nil {
		return err
	}

	parseIPs := ParseIPs{} // Create a new ParseIPs, which is a []net.IP under the hood
	// Validate IP ranges in c.Scope.IP
	for _, ipRange := range s.IP {
		if err := parseIPs.parseRange(ipRange); err != nil {
			return err
		}
	}
	// append parseIPs (which is a []net.IP) to c.Scope.IP
	s.Addresses = append(s.Addresses, parseIPs...)
	return nil
}

func (s *Scope) parsePorts() error {

	if len(s.PortsRaw) != 0 {
		s.Ports = []int{}
	}

	for _, port := range s.PortsRaw {
		switch p := port.(type) {
		case int: // If it's an integer, just append
			s.Ports = append(s.Ports, p)
		case string: // If it's a string, check if it's a range or a single port
			if strings.Contains(p, "-") {
				// Handle port range
				portRange, err := convertPortRangeToSlice(p)
				if err != nil {
					return err
				}
				s.Ports = append(s.Ports, portRange...)
			} else {
				// Handle single port string
				portNum, err := strconv.Atoi(p)
				if err != nil {
					return fmt.Errorf("invalid port string: %v", err)
				}
				s.Ports = append(s.Ports, portNum)
			}
		default:
			return fmt.Errorf("unsupported port type: %T", p)
		}
	}

	return nil
}

func convertPortRangeToSlice(portRange string) ([]int, error) {
	var ports []int

	parts := strings.Split(portRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid port range format")
	}

	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid start port: %v", err)
	}

	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid end port: %v", err)
	}

	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}

	return ports, nil
}

// returns true is ports match default ports (80,443), otherwise return false
func portCheck(ports []int) bool {
	defaultPorts := []int{80, 443}
	if len(ports) != len(defaultPorts) {
		return false
	}
	for i, v := range ports {
		if v != defaultPorts[i] {
			return false
		}
	}
	return true
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
		c.Scope.Domains = append(c.Scope.Domains, d)
	}

	c.Scope.Domains = stringset.Deduplicate(c.Scope.Domains)
}

// Domains returns the list of domain names currently in the configuration.
func (c *Config) Domains() []string {
	c.Lock()
	defer c.Unlock()

	return c.Scope.Domains
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

	if len(c.Scope.Addresses) == 0 && len(c.Scope.CIDRs) == 0 {
		return false
	}
	for _, cidr := range c.Scope.CIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	for _, a := range c.Scope.Addresses {
		if a.Equal(ip) {
			return true
		}
	}
	return false
}

// BlacklistSubdomain adds a subdomain name to the config blacklist.
func (c *Config) BlacklistSubdomain(name string) {
	c.blacklistLock.Lock()
	defer c.blacklistLock.Unlock()

	set := stringset.New(c.Scope.Blacklist...)
	defer set.Close()
	set.Insert(strings.TrimSpace(name))

	c.Scope.Blacklist = set.Slice()
}

// Blacklisted returns true is the name in the parameter ends with a subdomain name in the config blacklist.
func (c *Config) Blacklisted(name string) bool {
	c.blacklistLock.Lock()
	defer c.blacklistLock.Unlock()

	n := strings.ToLower(strings.TrimSpace(name))

	for _, bl := range c.Scope.Blacklist {
		if hasPathSuffix(n, bl) {
			return true
		}
	}

	return false
}

// ParseIPs represents a slice of net.IP addresses.
type ParseIPs []net.IP

func (p *ParseIPs) String() string {
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
func (p *ParseIPs) Set(s string) error {
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

func (p *ParseIPs) appendIPs(addrs []net.IP) error {
	for _, addr := range addrs {
		*p = append(*p, addr)
	}
	return nil
}

func (p *ParseIPs) parseRange(s string) error {
	twoIPs := strings.Split(s, "-")

	// If s is not a range, try parsing it as a single IP
	if twoIPs[0] == s {
		ip := net.ParseIP(s)
		if ip == nil {
			return fmt.Errorf("%s is not a valid IP", s)
		}
		return p.appendIPs([]net.IP{ip})
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
