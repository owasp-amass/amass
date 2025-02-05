// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// DataSource contains the configurations specific to a data source.
type DataSource struct {
	Name  string                  `yaml:"name,omitempty" json:"name,omitempty"`
	TTL   int                     `yaml:"ttl,omitempty" json:"ttl,omitempty"`
	Creds map[string]*Credentials `yaml:"creds,omitempty" json:"creds,omitempty"`
}

// Credentials contains values required for authenticating with web APIs.
type Credentials struct {
	Name     string `yaml:"-" json:"-"`
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
	Apikey   string `yaml:"apikey,omitempty" json:"apikey,omitempty"`
	Secret   string `yaml:"secret,omitempty" json:"secret,omitempty"`
}

// DataSourceConfig contains the configuration for multiple data sources.
type DataSourceConfig struct {
	Datasources   []*DataSource  `yaml:"datasources,omitempty" json:"datasources,omitempty"`
	GlobalOptions map[string]int `yaml:"global_options,omitempty" json:"global_options,omitempty"`
}

// GetDataSourceConfig returns the DataSourceConfig associated with the data source name argument.
func (c *Config) GetDataSourceConfig(source string) *DataSource {
	c.Lock()
	defer c.Unlock()

	key := strings.ToLower(strings.TrimSpace(source))
	if key == "" || c.DataSrcConfigs == nil {
		return nil
	}

	var dsc *DataSource
	for _, src := range c.DataSrcConfigs.Datasources {
		if strings.ToLower(src.Name) == key {
			dsc = src
			break
		}
	}
	return dsc
}

// AddCredentials adds the Credentials provided to the configuration.
func (ds *DataSource) AddCredentials(accountName string, cred *Credentials) error {
	if accountName == "" || ds == nil {
		return fmt.Errorf("AddCredentials: The accountName argument is invalid")
	}

	if ds.Creds == nil {
		ds.Creds = make(map[string]*Credentials)
	}

	ds.Creds[accountName] = cred
	return nil
}

// GetCredentials returns the first set of Credentials associated with the given DataSource name.
func (dsc *DataSourceConfig) GetCredentials(dsName string) *Credentials {
	if dsc == nil || dsc.Datasources == nil {
		return nil
	}

	for _, src := range dsc.Datasources {
		if src.Name == dsName && src.Creds != nil {
			for _, creds := range src.Creds {
				return creds // Return the first set of credentials found
			}
		}
	}
	return nil
}

func (c *Config) loadDataSourceSettings(cfg *Config) error {
	// Retrieve the datasources file path from the options
	pathInterface, ok := c.Options["datasources"]
	if !ok {
		// "datasources" not found in options, so nothing to do here.
		return nil
	}

	path, ok := pathInterface.(string)
	if !ok {
		return fmt.Errorf("datasources option is not a string")
	}
	// Construct the absolute path by joining the current working directory and the relative path
	absPath, err := c.AbsPathFromConfigDir(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}
	// Load the datasources YAML file
	data, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("error reading datasources file: %v", err)
	}
	// Unmarshal the YAML data into a DataSourceConfig
	var dsConfig DataSourceConfig
	err = yaml.Unmarshal(data, &dsConfig)
	if err != nil {
		return fmt.Errorf("error unmarshalling datasources YAML: %v", err)
	}

	dsConfig.MapNames()
	// Assign the unmarshalled DataSourceConfig to the Config struct
	c.DataSrcConfigs = &dsConfig
	c.DataSrcConfigs.ttlCheck()
	return nil
}

func (dsc *DataSourceConfig) ttlCheck() {
	// The global minimum TTL is already loaded during the YAML unmarshalling process
	for _, ds := range dsc.Datasources {
		// Ensure the TTL is not less than the global minimum
		if dsc.GlobalOptions != nil {
			if minTTL, ok := dsc.GlobalOptions["minimum_ttl"]; ok && minTTL > ds.TTL {
				ds.TTL = dsc.GlobalOptions["minimum_ttl"]
			}
		} else {
			break
		}
	}
}

// MapNames assigns the name of the DataSource to each associated Credential's Name field.
// This is especially useful after unmarshalling data where the relationship between a DataSource and its
// credentials may not have been explicitly set in the source data.
func (dsc *DataSourceConfig) MapNames() {
	// Assign the DataSource name to each Credential's Name field in the Datasource
	for _, src := range dsc.Datasources {
		if src.Creds == nil {
			src.Creds = make(map[string]*Credentials)
		}

		for accountName, creds := range src.Creds {
			creds.Name = src.Name
			src.Creds[accountName] = creds
		}
	}
}
