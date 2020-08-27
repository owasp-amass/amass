// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"strings"

	"github.com/OWASP/Amass/v3/stringset"
	"github.com/go-ini/ini"
)

// APIKey contains values required for authenticating with web APIs.
type APIKey struct {
	Username string `ini:"username"`
	Password string `ini:"password"`
	Key      string `ini:"apikey"`
	Secret   string `ini:"secret"`
	TTL      int    `ini:"ttl"`
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

func (c *Config) loadDataSourceSettings(cfg *ini.File) error {
	sec, err := cfg.GetSection("data_sources")
	if err != nil {
		return nil
	}

	if sec.HasKey("minimum_ttl") {
		if ttl, err := sec.Key("minimum_ttl").Int(); err == nil {
			c.MinimumTTL = ttl
		}
	}

	for _, child := range sec.ChildSections() {
		name := strings.Split(child.Name(), ".")[1]

		if name == "disabled_data_sources" {
			// Load up all the disabled data source names
			c.SourceFilter.Sources = stringset.Deduplicate(child.Key("data_source").ValueWithShadows())
			c.SourceFilter.Include = false
			continue
		}

		key := new(APIKey)
		// Parse the Database information and assign to the Config
		if err := child.MapTo(key); err == nil {
			if c.MinimumTTL > key.TTL {
				key.TTL = c.MinimumTTL
			}

			c.AddAPIKey(name, key)
		}
	}

	return nil
}
