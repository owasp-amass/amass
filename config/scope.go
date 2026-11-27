// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/caffix/stringset"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	"github.com/owasp-amass/amass/v5/internal/net/dns"
	"golang.org/x/net/publicsuffix"
)

func (c *Config) loadSeedandScopeSettings() error {
	// A scope section with every entry commented out decodes as null: it
	// restricts nothing, and the default ports apply.
	if c.Scope == nil {
		c.Scope = &Scope{Ports: slices.Clone(DefaultPorts)}
	}
	if err := c.Scope.populate(); err != nil {
		return err
	}
	// Seed DNS names (leads) may be listed inline and in a file; load the
	// file into the inline list before deciding whether the seed is empty.
	if c.Seed != nil && c.Seed.NamesFile != "" {
		list, err := GetListFromFile(c.Seed.NamesFile)
		if err != nil {
			return fmt.Errorf("failed to read the seed names file %q: %v", c.Seed.NamesFile, err)
		}

		c.Seed.Names = append(c.Seed.Names, list...)
	}

	if c.Seed == nil || c.Seed.isScopeEmpty(false) {
		// Without a seed, the whole scope is where the enumeration starts.
		c.Seed = c.Scope
	} else {
		if err := c.Seed.populate(); err != nil {
			return err
		}

		// The seed is where the enumeration starts, and it is in scope as
		// well: the scope boundary is the scope section's entries and the
		// seed's, with the scope section's ports (the default ports when it
		// lists none).
		c.Scope.merge(c.Seed)
	}

	// Seed names are leads the enumeration starts from, so they join the
	// provided names and their registered domains join the scope boundary.
	c.AddSeedNames(c.Seed.Names...)
	return nil
}

// HasSeed reports whether the enumeration has at least one starting point:
// a seed (or scope, when no seed was given) entry of any kind, or a
// provided name. A run with none has nothing to begin from.
func (c *Config) HasSeed() bool {
	return len(c.ProvidedNames) > 0 || !c.SeedScope().isScopeEmpty(false)
}

// SeedScope returns where the enumeration starts: the seed when one was
// given, otherwise the whole scope. It is resolved at seed time so that
// command-line targets, which populate the scope, are the start when no
// explicit seed was configured.
func (c *Config) SeedScope() *Scope {
	if c.Seed != nil && !c.Seed.isScopeEmpty(false) {
		return c.Seed
	}

	return c.Scope
}

// AddSeedNames records known DNS names as leads the enumeration starts from:
// each is added to the provided names submitted to the engine, and its
// registered domain is added to the scope boundary so the lead is never
// dropped as out of scope. It does not make the registered domain a seed on
// its own. A name whose registered domain cannot be determined is still
// submitted as a provided name.
func (c *Config) AddSeedNames(names ...string) {
	for _, n := range names {
		name := strings.ToLower(strings.TrimSpace(n))
		if name == "" {
			continue
		}
		if !slices.Contains(c.ProvidedNames, name) {
			c.ProvidedNames = append(c.ProvidedNames, name)
		}
		if dom, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && dom != "" {
			c.AddDomain(dom)
		}
	}
}

// merge adds the names, addresses, networks, autonomous systems and
// blacklisted names of o that s does not already have.
func (s *Scope) merge(o *Scope) {
	for _, d := range o.Domains {
		if !slices.ContainsFunc(s.Domains, func(x string) bool { return strings.EqualFold(x, d) }) {
			s.Domains = append(s.Domains, d)
		}
	}
	for _, ip := range o.IP {
		if !slices.Contains(s.IP, ip) {
			s.IP = append(s.IP, ip)
		}
	}
	for _, a := range o.Addresses {
		if !slices.ContainsFunc(s.Addresses, a.Equal) {
			s.Addresses = append(s.Addresses, a)
		}
	}
	for _, cidr := range o.CIDRStrings {
		if !slices.Contains(s.CIDRStrings, cidr) {
			s.CIDRStrings = append(s.CIDRStrings, cidr)
		}
	}
	for _, n := range o.CIDRs {
		if !slices.ContainsFunc(s.CIDRs, func(x *net.IPNet) bool { return x.String() == n.String() }) {
			s.CIDRs = append(s.CIDRs, n)
		}
	}
	for _, asn := range o.ASNs {
		if !slices.Contains(s.ASNs, asn) {
			s.ASNs = append(s.ASNs, asn)
		}
	}
	for _, org := range o.Organizations {
		if !slices.ContainsFunc(s.Organizations, func(x string) bool { return strings.EqualFold(x, org) }) {
			s.Organizations = append(s.Organizations, org)
		}
	}
	for _, b := range o.Blacklist {
		if !slices.Contains(s.Blacklist, b) {
			s.Blacklist = append(s.Blacklist, b)
		}
	}
}

func (s *Scope) isScopeEmpty(scopeSwitch bool) bool {
	if len(s.Domains) > 0 {
		return false
	}
	if len(s.Addresses) > 0 {
		return false
	}
	if len(s.CIDRs) > 0 {
		return false
	}
	if len(s.ASNs) > 0 {
		return false
	}
	if len(s.IP) > 0 {
		return false
	}
	if len(s.Organizations) > 0 {
		return false
	}
	if len(s.Phones) > 0 || len(s.StreetAddresses) > 0 {
		return false
	}
	if len(s.Names) > 0 || s.NamesFile != "" {
		return false
	}
	if scopeSwitch && portCheck(s.Ports) {
		return false
	} else if len(s.Ports) > 0 {
		return false
	}
	if len(s.Blacklist) > 0 {
		return false
	}
	return true
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

// portCheck reports whether ports are the default ports, DefaultPorts.
func portCheck(ports []int) bool {
	defaultPorts := DefaultPorts

	portSet := make(map[int]struct{}, len(ports))
	for _, v := range ports {
		portSet[v] = struct{}{}
	}
	if len(portSet) > len(defaultPorts) {
		return false
	}
	for _, v := range defaultPorts {
		if _, found := portSet[v]; !found {
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

// AddPhone records a phone number as a seed the enumeration pivots from: the
// engine resolves the organizations tied to the number and their domains.
func (c *Config) AddPhone(phone string) {
	c.Lock()
	defer c.Unlock()

	p := strings.TrimSpace(phone)
	if p == "" || slices.Contains(c.Scope.Phones, p) {
		return
	}
	c.Scope.Phones = append(c.Scope.Phones, p)
}

// AddStreetAddress records a street address as a seed the enumeration pivots from:
// the engine resolves the organizations at the address and their domains.
func (c *Config) AddStreetAddress(address string) {
	c.Lock()
	defer c.Unlock()

	a := strings.TrimSpace(address)
	if a == "" || slices.Contains(c.Scope.StreetAddresses, a) {
		return
	}
	c.Scope.StreetAddresses = append(c.Scope.StreetAddresses, a)
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

// IsPhoneInScope reports whether the phone number is one of the scope's phone
// seeds, compared by digits, so a number matches however it is written.
func (c *Config) IsPhoneInScope(phone string) bool {
	want := phoneDigits(phone)
	if want == "" || c.Scope == nil {
		return false
	}

	c.Lock()
	defer c.Unlock()
	for _, p := range c.Scope.Phones {
		if phoneDigits(p) == want {
			return true
		}
	}
	return false
}

func phoneDigits(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
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
