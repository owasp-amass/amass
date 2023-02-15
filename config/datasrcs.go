// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/caffix/stringset"
	"github.com/go-ini/ini"
)

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

// GetDataSourceConfig returns the DataSourceConfig associated with the data source name argument.
func (c *Config) GetDataSourceConfig(source string) *DataSourceConfig {
	c.Lock()
	defer c.Unlock()

	key := strings.ToLower(strings.TrimSpace(source))
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

// GetCredentials returns randomly selected Credentials associated with the receiver configuration.
func (dsc *DataSourceConfig) GetCredentials() *Credentials {
	if num := len(dsc.creds); num > 0 {
		var creds []*Credentials
		for _, c := range dsc.creds {
			creds = append(creds, c)
		}
		return creds[rand.Intn(num)]
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
			// Load up all the disabled data source names
			c.SourceFilter.Sources = stringset.Deduplicate(child.Key("data_source").ValueWithShadows())
			c.SourceFilter.Include = false
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
