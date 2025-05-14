// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/utils/net/http"
)

// DefaultQueriesPerPublicResolver is the number of queries sent to each public DNS resolver per second.
const DefaultQueriesPerPublicResolver = 5

// DefaultQueriesPerBaselineResolver is the number of queries sent to each trusted DNS resolver per second.
const DefaultQueriesPerBaselineResolver = 15
const minResolverReliability = 0.85

// DefaultBaselineResolvers is a list of trusted public DNS resolvers.
var DefaultBaselineResolvers = []string{
	"8.8.8.8",        // Google
	"1.1.1.1",        // Cloudflare
	"9.9.9.9",        // Quad9
	"208.67.222.222", // Cisco OpenDNS
	"84.200.69.80",   // DNS.WATCH
	"64.6.64.6",      // Neustar DNS
	"8.26.56.26",     // Comodo Secure DNS
	"205.171.3.65",   // Level3
	"134.195.4.2",    // OpenNIC
	"185.228.168.9",  // CleanBrowsing
	"76.76.19.19",    // Alternate DNS
	"37.235.1.177",   // FreeDNS
	"77.88.8.1",      // Yandex.DNS
	"94.140.14.140",  // AdGuard
	"38.132.106.139", // CyberGhost
	"74.82.42.42",    // Hurricane Electric
	"76.76.2.0",      // ControlD
}

// PublicResolvers includes the addresses of public resolvers obtained dynamically.
var PublicResolvers []string

// GetPublicDNSResolvers obtains the public DNS server addresses from public-dns.info and assigns them to PublicResolvers.
func GetPublicDNSResolvers() error {
	url := "https://public-dns.info/nameservers-all.csv"
	resp, err := http.RequestWebPage(context.Background(), &http.Request{URL: url})
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("failed to obtain the Public DNS csv file at %s: %v", url, err)
	}

	var resolvers []string
	var ipIdx, reliabilityIdx int
	r := csv.NewReader(strings.NewReader(resp.Body))
	for i := 0; ; i++ {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		if i == 0 {
			for idx, val := range record {
				switch val {
				case "ip_address":
					ipIdx = idx
				case "reliability":
					reliabilityIdx = idx
				}
			}
			continue
		}
		if rel, err := strconv.ParseFloat(record[reliabilityIdx], 64); err == nil && rel >= minResolverReliability {
			resolvers = append(resolvers, record[ipIdx])
		}
	}
loop:
	for _, addr := range resolvers {
		for _, br := range DefaultBaselineResolvers {
			if addr == br {
				continue loop
			}
		}
		PublicResolvers = append(PublicResolvers, addr)
	}
	return nil
}

// SetResolvers assigns the untrusted resolver names provided in the parameter to the list in the configuration.
func (c *Config) SetResolvers(resolvers ...string) {
	c.Resolvers = []string{}
	c.AddResolvers(resolvers...)
}

// AddResolvers appends the untrusted resolver names provided in the parameter to the list in the configuration.
func (c *Config) AddResolvers(resolvers ...string) {
	for _, r := range resolvers {
		c.AddResolver(r)
	}
	c.CalcMaxQPS()
}

// AddResolver appends the untrusted resolver name provided in the parameter to the list in the configuration.
func (c *Config) AddResolver(resolver string) {
	c.Lock()
	defer c.Unlock()

	// Check that the domain string is not empty
	r := strings.TrimSpace(resolver)
	if r == "" {
		return
	}

	c.Resolvers = stringset.Deduplicate(append(c.Resolvers, resolver))
}

// SetTrustedResolvers assigns the trusted resolver names provided in the parameter to the list in the configuration.
func (c *Config) SetTrustedResolvers(resolvers ...string) {
	c.Resolvers = []string{}
	c.AddResolvers(resolvers...)
}

// AddTrustedResolvers appends the trusted resolver names provided in the parameter to the list in the configuration.
func (c *Config) AddTrustedResolvers(resolvers ...string) {
	for _, r := range resolvers {
		c.AddTrustedResolver(r)
	}
	c.CalcMaxQPS()
}

// AddTrustedResolver appends the trusted resolver name provided in the parameter to the list in the configuration.
func (c *Config) AddTrustedResolver(resolver string) {
	c.Lock()
	defer c.Unlock()

	// Check that the domain string is not empty
	r := strings.TrimSpace(resolver)
	if r == "" {
		return
	}

	c.TrustedResolvers = stringset.Deduplicate(append(c.TrustedResolvers, resolver))
}

// CalcMaxQPS updates the MaxDNSQueries field of the configuration based on current settings.
func (c *Config) CalcMaxQPS() {
	c.MaxDNSQueries = (len(c.Resolvers) * c.ResolversQPS) + (len(c.TrustedResolvers) * c.TrustedQPS)
}

func (c *Config) loadResolverSettings(cfg *Config) error {
	// Fetch resolvers from the Options map in the Config.
	resolversRaw, ok := c.Options["resolvers"]
	if !ok {
		// "resolvers" not found in options, so nothing to do here.
		return nil
	}

	// Type assert the raw resolvers to []interface{}
	resolvers, ok := resolversRaw.([]interface{})
	if !ok {
		return errors.New("resolvers section is not a list")
	}

	var resolversList []string
	for _, r := range resolvers {
		// Type assert the resolver to string
		rStr, ok := r.(string)
		if !ok {
			return fmt.Errorf("resolver entry %v is not a string", r)
		}

		// Check if rStr is an IP address.
		ip := net.ParseIP(rStr)
		if ip != nil {
			resolversList = append(resolversList, rStr)
			continue
		}

		// rStr is not an IP address, so we assume it is a file path.
		absPath, err := c.AbsPathFromConfigDir(rStr)
		if err != nil {
			return fmt.Errorf("failed to get absolute path for resolver file: %w", err)
		}

		fileResolvers, err := c.loadResolversFromFile(absPath)
		if err != nil {
			return fmt.Errorf("failed to load resolvers from file: %w", err)
		}

		resolversList = append(resolversList, fileResolvers...)

	}

	// Deduplicate the list of resolvers and assign to c.Resolvers.
	resolverIPs := stringset.Deduplicate(resolversList)

	if len(resolverIPs) == 0 {
		return errors.New("no valid resolvers were found")
	}

	c.Resolvers = resolverIPs

	return nil
}

func (c *Config) loadResolversFromFile(path string) ([]string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open resolvers file: %w", err)
	}

	// Split the file data by newlines to get the IP addresses.
	lines := strings.Split(string(data), "\n")

	var resolvers []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Skip empty lines.
		if line == "" {
			continue
		}

		// Check if each line in the file is a valid IP address.
		ip := net.ParseIP(line)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address in resolvers file: %s", line)
		}

		resolvers = append(resolvers, line)
	}

	return resolvers, nil
}
