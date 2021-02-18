// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"testing"

	"github.com/go-ini/ini"
)

func TestGetDataSourceConfig(t *testing.T) {
	name := "test"
	c := NewConfig()

	if dsc := c.GetDataSourceConfig(""); dsc != nil {
		t.Errorf("GetDataSourceConfig returned a non-nil value when provided an invalid argument")
	}

	if dsc := c.GetDataSourceConfig(name); dsc == nil || dsc.Name != name {
		t.Errorf("GetDataSourceConfig returned an error when provided a valid argument")
	}
}

func TestAddCredentials(t *testing.T) {
	name := "test"
	c := NewConfig()
	dsc := c.GetDataSourceConfig(name)

	if err := dsc.AddCredentials(nil); err == nil {
		t.Errorf("AddCredentials returned no error when provided an invalid Credentials argument")
	}
	if err := dsc.AddCredentials(&Credentials{Name: "account1"}); err != nil {
		t.Errorf("AddCredentials returned an error when provided an valid arguments: %v", err)
	}
	if dsc := c.GetDataSourceConfig(name); dsc == nil || dsc.creds["account1"].Name != "account1" {
		t.Errorf("AddCredentials failed to enter the new credentials into the data source configuration")
	}
}

func TestGetCredentials(t *testing.T) {
	c := NewConfig()
	dsc := c.GetDataSourceConfig("test")

	if creds := dsc.GetCredentials(); creds != nil {
		t.Errorf("GetCredentials returned non-nil value when the receiver had no credentials")
	}

	if err := dsc.AddCredentials(&Credentials{Name: "account1"}); err != nil {
		t.Errorf("AddCredentials returned an error: %v", err)
	}
	if creds := dsc.GetCredentials(); creds == nil || creds.Name != "account1" {
		t.Errorf("GetCredentials returned an error when provided a valid argument")
	}
}

func TestLoadDataSourceSettings(t *testing.T) {
	c := NewConfig()

	cfg, _ := ini.LoadSources(
		ini.LoadOptions{
			Insensitive:  true,
			AllowShadows: true,
		},
		[]byte(`
		[mysection]
		msg = Hello
		`),
	)

	if err := c.loadDataSourceSettings(cfg); err == nil {
		t.Errorf("Failed to report an error when attempting to load another section type")
	}

	cfg, _ = ini.LoadSources(
		ini.LoadOptions{
			Insensitive:  true,
			AllowShadows: true,
		},
		[]byte(`
		[data_sources]
		minimum_ttl = 1440

		[data_sources.disabled]
		data_source = CommonCrawl

		[data_sources.AlienVault]
		ttl = 4320
		[data_sources.AlienVault.Credentials]
		apikey = fake

		[data_sources.BinaryEdge]
		[data_sources.BinaryEdge.Credentials]
		apikey = fake2
		`),
	)

	if err := c.loadDataSourceSettings(cfg); err != nil {
		t.Errorf("Failed to parse the data source settings: %v", err)
	}
	if c.MinimumTTL != 1440 {
		t.Errorf("Failed to load global data source settings")
	}

	dsc := c.GetDataSourceConfig("AlienVault")
	if dsc == nil {
		t.Errorf("Failed to load data source settings")
	}
	if creds := dsc.GetCredentials(); creds == nil || creds.Key != "fake" {
		t.Errorf("Failed to load data source credentials")
	}
}
