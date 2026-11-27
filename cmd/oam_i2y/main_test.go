// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	"gopkg.in/yaml.v3"
)

func loadLegacy(t *testing.T) *Config {
	t.Helper()
	c := &Config{}
	if err := c.LoadSettings(filepath.Join("testdata", "legacy.ini")); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadSettings(t *testing.T) {
	c := loadLegacy(t)

	if !c.Passive || c.Active {
		t.Error("the passive mode was not read")
	}
	if !reflect.DeepEqual(c.Resolvers, []string{"8.8.8.8", "1.1.1.1"}) {
		t.Errorf("resolvers = %v", c.Resolvers)
	}
	if !reflect.DeepEqual(c.Addresses, []string{"192.0.2.1", "192.0.2.2"}) ||
		!reflect.DeepEqual(c.CIDRs, []string{"198.51.100.0/24"}) {
		t.Errorf("addresses = %v, cidrs = %v", c.Addresses, c.CIDRs)
	}
	// numbers are kept once each; a value that is not a number is dropped
	if !reflect.DeepEqual(c.ASNs, []int{64496, 64497}) || !reflect.DeepEqual(c.Ports, []int{80, 443}) {
		t.Errorf("asns = %v, ports = %v", c.ASNs, c.Ports)
	}
	// a single label or an empty label is not a domain
	if !reflect.DeepEqual(c.domains, []string{"example.com", "example.org"}) {
		t.Errorf("domains = %v", c.domains)
	}
	if !reflect.DeepEqual(c.Blacklist, []string{"internal.example.com"}) {
		t.Errorf("blacklist = %v", c.Blacklist)
	}
	if len(c.GraphDBs) != 1 || c.GraphDBs[0].System != "postgres" || !c.GraphDBs[0].Primary ||
		c.GraphDBs[0].URL != "postgres://amass:secret@127.0.0.1:5432/assetdb" {
		t.Errorf("graph databases = %+v", c.GraphDBs)
	}
	if !c.BruteForcing || !reflect.DeepEqual(c.Bruteforcelist, []string{"/words/names.txt"}) || c.Alterations {
		t.Errorf("bruteforce = %v %v, alterations = %v", c.BruteForcing, c.Bruteforcelist, c.Alterations)
	}

	// a data source's TTL is raised to the minimum
	if c.MinimumTTL != 1440 {
		t.Errorf("minimum TTL = %d", c.MinimumTTL)
	}
	shodan := c.GetDataSourceConfig("shodan")
	if shodan.TTL != 1440 || shodan.creds["credentials"] == nil || shodan.creds["credentials"].Key != "shodan-key" {
		t.Errorf("shodan = %+v, creds %+v", shodan, shodan.creds)
	}
	if _, ok := c.datasrcConfigs["disabled"]; ok {
		t.Error("the disabled list was read as a data source")
	}
}

func TestLoadSettingsErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	if err := (&Config{}).LoadSettings(filepath.Join(dir, "missing.ini")); err == nil {
		t.Error("a missing file was loaded")
	}
	if err := (&Config{}).LoadSettings(write("cidr.ini", "[scope]\ncidr = 198.51.100.0/33\n")); err == nil {
		t.Error("an invalid CIDR was accepted")
	}
	if err := (&Config{}).LoadSettings(write("resolvers.ini", "[resolvers]\n")); err == nil {
		t.Error("an empty resolvers section was accepted")
	}
	// a configuration without data sources still converts
	c := &Config{}
	if err := c.LoadSettings(write("scope.ini", "[scope.domains]\ndomain = example.com\n")); err != nil {
		t.Errorf("a configuration without data sources: %v", err)
	}
	if !reflect.DeepEqual(c.domains, []string{"example.com"}) {
		t.Errorf("domains = %v", c.domains)
	}
}

func TestConvert(t *testing.T) {
	cfg, ds := convert(loadLegacy(t))

	// only the data sources with credentials, in name order
	if len(ds.Datasources) != 2 || ds.Datasources[0].Name != "censys" || ds.Datasources[1].Name != "shodan" {
		t.Fatalf("data sources = %+v", ds.Datasources)
	}
	censys := ds.Datasources[0].Creds["credentials"]
	if censys == nil || censys.Apikey != "censys-id" || censys.Secret != "censys-secret" {
		t.Errorf("censys credentials = %+v", censys)
	}
	if ds.GlobalOptions["minimum_ttl"] != 1440 {
		t.Errorf("global options = %v", ds.GlobalOptions)
	}

	if !reflect.DeepEqual(cfg.Scope.Domains, []string{"example.com", "example.org"}) ||
		!reflect.DeepEqual(cfg.Scope.ASNs, []int{64496, 64497}) ||
		!reflect.DeepEqual(cfg.Scope.CIDRStrings, []string{"198.51.100.0/24"}) {
		t.Errorf("scope = %+v", cfg.Scope)
	}
	if cfg.Options["database"] != "postgres://amass:secret@127.0.0.1:5432/assetdb" {
		t.Errorf("database = %v", cfg.Options["database"])
	}
	if bf, ok := cfg.Options["bruteforce"].(map[string]interface{}); !ok || bf["enabled"] != true {
		t.Errorf("bruteforce = %v", cfg.Options["bruteforce"])
	}
	if _, ok := cfg.Options["alterations"]; ok {
		t.Error("disabled alterations were written")
	}

	// the converted files are valid YAML that the current configuration reads
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var back config.Config
	if err := yaml.Unmarshal(data, &back); err != nil || back.Scope == nil ||
		!reflect.DeepEqual(back.Scope.Domains, cfg.Scope.Domains) {
		t.Errorf("round trip = %+v, %v", back.Scope, err)
	}
	data, err = yaml.Marshal(ds)
	if err != nil {
		t.Fatal(err)
	}
	var backDS config.DataSourceConfig
	if err := yaml.Unmarshal(data, &backDS); err != nil || len(backDS.Datasources) != 2 {
		t.Errorf("data source round trip = %+v, %v", backDS, err)
	}
}
