// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/OWASP/Amass/v3/net/http"
	"github.com/caffix/stringset"
	"github.com/go-ini/ini"
)

// DefaultQueriesPerPublicResolver is the number of queries sent to each public DNS resolver per second.
const DefaultQueriesPerPublicResolver = 10

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
	"8.26.56.26",     // Comodo Secure DNS
	"64.6.64.6",      // Neustar DNS
	"76.76.19.19",    // Alternate DNS
	"77.88.8.1",      // Yandex.DNS
	"216.146.35.35",  // Dyn
	"192.71.245.208", // OpenNIC
	"38.132.106.139", // CyberGhost
	"109.69.8.51",    // puntCAT
}

// PublicResolvers includes the addresses of public resolvers obtained dynamically.
var PublicResolvers []string

func init() {
	addrs, err := getPublicDNSResolvers()
	if err != nil {
		return
	}
loop:
	for _, addr := range addrs {
		for _, br := range DefaultBaselineResolvers {
			if addr == br {
				continue loop
			}
		}
		PublicResolvers = append(PublicResolvers, addr)
	}
}

// SetResolvers assigns the resolver names provided in the parameter to the list in the configuration.
func (c *Config) SetResolvers(resolvers ...string) {
	c.Resolvers = []string{}

	c.AddResolvers(resolvers...)
}

// AddResolvers appends the resolver names provided in the parameter to the list in the configuration.
func (c *Config) AddResolvers(resolvers ...string) {
	for _, r := range resolvers {
		c.AddResolver(r)
	}
}

// AddResolver appends the resolver name provided in the parameter to the list in the configuration.
func (c *Config) AddResolver(resolver string) {
	c.Lock()
	defer c.Unlock()

	// Check that the domain string is not empty
	r := strings.TrimSpace(resolver)
	if r == "" {
		return
	}

	c.Resolvers = stringset.Deduplicate(append(c.Resolvers, resolver))
	c.calcDNSQueriesMax()
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

func (c *Config) calcDNSQueriesMax() {
	c.MaxDNSQueries = len(c.Resolvers) * DefaultQueriesPerPublicResolver
}

func getPublicDNSResolvers() ([]string, error) {
	url := "https://public-dns.info/nameservers-all.csv"
	page, err := http.RequestWebPage(context.Background(), url, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain the Public DNS csv file at %s: %v", url, err)
	}

	var resolvers []string
	var ipIdx, reliabilityIdx int
	r := csv.NewReader(strings.NewReader(page))
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

	return resolvers, nil
}
