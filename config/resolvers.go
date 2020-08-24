// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"errors"
	"strings"

	"github.com/OWASP/Amass/v3/stringset"
	"github.com/go-ini/ini"
)

const defaultConcurrentDNSQueries = 4000

var defaultPublicResolvers = []string{
	"1.1.1.1",     // Cloudflare
	"8.8.8.8",     // Google
	"64.6.64.6",   // Verisign
	"74.82.42.42", // Hurricane Electric
	"1.0.0.1",     // Cloudflare Secondary
	"8.8.4.4",     // Google Secondary
	"64.6.65.6",   // Verisign Secondary
	"77.88.8.1",   // Yandex.DNS Secondary
}

// SetResolvers assigns the resolver names provided in the parameter to the list in the configuration.
func (c *Config) SetResolvers(resolvers []string) {
	c.Resolvers = []string{}

	for _, r := range resolvers {
		c.AddResolver(r)
	}
}

// AddResolvers appends the resolver names provided in the parameter to the list in the configuration.
func (c *Config) AddResolvers(resolvers []string) {
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
		return errors.New("No resolver keys were found in the resolvers section")
	}

	c.MonitorResolverRate = sec.Key("monitor_resolver_rate").MustBool(true)
	return nil
}

func (c *Config) calcDNSQueriesMax() {
	max := len(c.Resolvers) * 500

	if max < 500 {
		max = 500
	} else if max > 100000 {
		max = 100000
	}

	c.MaxDNSQueries = max
}
