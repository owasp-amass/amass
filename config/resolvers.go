// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/owasp-amass/amass/v3/net/http"
	"github.com/caffix/stringset"
	"github.com/go-ini/ini"
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
				if val == "ip_address" {
					ipIdx = idx
				} else if val == "reliability" {
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
