// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"sort"
	"strings"
	"unicode"

	"github.com/owasp-amass/amass/v5/config"
)

// EnvPrefix begins the environment variables that give a data source's
// credential: AMASS_SECRET_<SOURCE>_<FIELD>, the source's name in capitals
// with anything but letters and digits as underscores (AMASS_SECRET_SHODAN_APIKEY).
const EnvPrefix = "AMASS_SECRET_"

// account is the name filled credentials are kept under.
const account = "shared"

// SourceKey is how a data source's name reads in an environment variable;
// two names with the same key are the same source.
func SourceKey(source string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToUpper(r)
		}
		return '_'
	}, strings.TrimSpace(source))
}

// envCredentials reads the credentials in the environment, by source.
func envCredentials(environ []string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || value == "" || !strings.HasPrefix(name, EnvPrefix) {
			continue
		}
		rest := strings.TrimPrefix(name, EnvPrefix)
		i := strings.LastIndexByte(rest, '_')
		if i <= 0 {
			continue
		}
		source, field := rest[:i], strings.ToLower(rest[i+1:])
		if !validField(field) {
			continue
		}
		if out[source] == nil {
			out[source] = map[string]string{}
		}
		out[source][field] = value
	}
	return out
}

// Fill gives each data source the configuration has no credentials for
// (the datasources file comes first) those of the next provider that has
// them: the environment (EnvPrefix), then the store, when there is one. A
// source takes all of its credentials from one provider. It returns the
// sources filled.
func Fill(cfg *config.Config, store *Store, environ []string) ([]string, error) {
	type candidate struct {
		name   string
		fields map[string]string
	}
	byKey := map[string]candidate{}
	if store != nil {
		values, _, err := store.Values()
		if err != nil {
			return nil, err
		}
		for source, fields := range values {
			byKey[SourceKey(source)] = candidate{name: source, fields: fields}
		}
	}
	// the environment comes before the store
	for key, fields := range envCredentials(environ) {
		name := strings.ToLower(key)
		if c, ok := byKey[key]; ok {
			name = c.name
		}
		byKey[key] = candidate{name: name, fields: fields}
	}
	if len(byKey) == 0 {
		return nil, nil
	}

	cfg.Lock()
	defer cfg.Unlock()
	if cfg.DataSrcConfigs == nil {
		cfg.DataSrcConfigs = &config.DataSourceConfig{}
	}
	dsc := cfg.DataSrcConfigs

	var filled []string
	for key, c := range byKey {
		var ds *config.DataSource
		for _, d := range dsc.Datasources {
			if d != nil && SourceKey(d.Name) == key {
				ds = d
				break
			}
		}
		if ds != nil && hasCredentials(ds) {
			continue
		}
		if ds == nil {
			ds = &config.DataSource{Name: c.name}
			if minTTL, ok := dsc.GlobalOptions["minimum_ttl"]; ok {
				ds.TTL = minTTL
			}
			dsc.Datasources = append(dsc.Datasources, ds)
		}
		_ = ds.AddCredentials(account, &config.Credentials{Name: ds.Name, Apikey: c.fields["apikey"],
			Secret: c.fields["secret"], Username: c.fields["username"], Password: c.fields["password"]})
		filled = append(filled, ds.Name)
	}
	sort.Strings(filled)
	return filled, nil
}

// Providers of credentials Sources reports.
const (
	FromEnvironment = "environment"
	FromDatabase    = "database"
)

// Sources reports, by SourceKey, the provider that has credentials for each
// data source outside the datasources file: the environment before the
// store. The store's secrets are listed, not opened.
func Sources(store *Store, environ []string) (map[string]string, error) {
	out := map[string]string{}
	if store != nil {
		entries, err := store.List()
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			out[SourceKey(e.Source)] = FromDatabase
		}
	}
	for key := range envCredentials(environ) {
		out[key] = FromEnvironment
	}
	return out, nil
}

// hasCredentials reports whether a data source has any credential set.
func hasCredentials(ds *config.DataSource) bool {
	for _, c := range ds.Creds {
		if c != nil && (c.Apikey != "" || c.Secret != "" || c.Username != "" || c.Password != "") {
			return true
		}
	}
	return false
}
