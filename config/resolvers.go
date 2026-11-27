// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/caffix/stringset"
)

// SetResolvers replaces the untrusted resolvers with the ones provided.
// Queries go to the untrusted resolvers when the configuration has any.
func (c *Config) SetResolvers(resolvers ...string) {
	c.Lock()
	c.Resolvers = nil
	c.Unlock()

	c.AddResolvers(resolvers...)
}

// AddResolvers appends the untrusted resolvers provided.
func (c *Config) AddResolvers(resolvers ...string) {
	for _, r := range resolvers {
		c.AddResolver(r)
	}
}

// AddResolver appends the untrusted resolver provided.
func (c *Config) AddResolver(resolver string) {
	c.Lock()
	defer c.Unlock()

	if r := strings.TrimSpace(resolver); r != "" {
		c.Resolvers = stringset.Deduplicate(append(c.Resolvers, r))
	}
}

// SetTrustedResolvers replaces the trusted resolvers with the ones provided.
// The first trusted resolver tests for DNS wildcards, and the trusted
// resolvers take the queries when there are no untrusted ones.
func (c *Config) SetTrustedResolvers(resolvers ...string) {
	c.Lock()
	c.TrustedResolvers = nil
	c.Unlock()

	c.AddTrustedResolvers(resolvers...)
}

// AddTrustedResolvers appends the trusted resolvers provided.
func (c *Config) AddTrustedResolvers(resolvers ...string) {
	for _, r := range resolvers {
		c.AddTrustedResolver(r)
	}
}

// AddTrustedResolver appends the trusted resolver provided.
func (c *Config) AddTrustedResolver(resolver string) {
	c.Lock()
	defer c.Unlock()

	if r := strings.TrimSpace(resolver); r != "" {
		c.TrustedResolvers = stringset.Deduplicate(append(c.TrustedResolvers, r))
	}
}

// loadResolverSettings reads options.resolvers and options.trusted_resolvers.
// Each entry is a resolver's IP address, with an optional port, or the path
// of a file listing one resolver per line.
func (c *Config) loadResolverSettings(cfg *Config) error {
	untrusted, err := c.resolverOption("resolvers")
	if err != nil {
		return err
	}
	trusted, err := c.resolverOption("trusted_resolvers")
	if err != nil {
		return err
	}

	if untrusted != nil {
		c.Resolvers = untrusted
	}
	if trusted != nil {
		c.TrustedResolvers = trusted
	}
	return nil
}

// resolverOption returns the resolvers listed under the option key, or nil
// when the option is absent.
func (c *Config) resolverOption(key string) ([]string, error) {
	raw, ok := c.Options[key]
	if !ok {
		return nil, nil
	}

	entries, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s section is not a list", key)
	}

	var list []string
	for _, r := range entries {
		entry, ok := r.(string)
		if !ok {
			return nil, fmt.Errorf("%s entry %v is not a string", key, r)
		}

		entry = strings.TrimSpace(entry)
		if IsResolverAddress(entry) {
			list = append(list, entry)
			continue
		}

		// Not an address, so the entry is the path of a file of resolvers.
		absPath, err := c.AbsPathFromConfigDir(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute path for resolver file: %w", err)
		}

		fileResolvers, err := c.loadResolversFromFile(absPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load resolvers from file: %w", err)
		}
		list = append(list, fileResolvers...)
	}

	list = stringset.Deduplicate(list)
	if len(list) == 0 {
		return nil, fmt.Errorf("no valid %s were found", strings.ReplaceAll(key, "_", " "))
	}
	return list, nil
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

	var resolvers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !IsResolverAddress(line) {
			return nil, fmt.Errorf("invalid resolver address in resolvers file: %s", line)
		}
		resolvers = append(resolvers, line)
	}
	if len(resolvers) == 0 {
		return nil, errors.New("the resolvers file lists no resolvers")
	}
	return resolvers, nil
}

// IsResolverAddress reports whether s is a resolver's IP address, with an
// optional port.
func IsResolverAddress(s string) bool {
	host := strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host) != nil
}
