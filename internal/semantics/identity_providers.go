// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed identity_providers.json
var identityProvidersJSON []byte

// IdentityProvider is a hosted identity service: the host suffixes of its
// tenants, and where a tenant names its organization identifier.
type IdentityProvider struct {
	Name       string   `json:"name"`
	Suffixes   []string `json:"suffixes"`
	TenantType string   `json:"tenant_type,omitempty"`
	TenantPath string   `json:"tenant_path,omitempty"`
	Source     string   `json:"source"`
}

// IdentityProviders is how a domain's identity provider is found. Loaded
// from identity_providers.json; see that file's _about.
type IdentityProviders struct {
	License                string             `json:"_license"`
	About                  string             `json:"_about"`
	OIDCPath               string             `json:"oidc_path"`
	OIDCSource             string             `json:"oidc_source"`
	FederationMetadataPath string             `json:"federation_metadata_path"`
	FederationSource       string             `json:"federation_source"`
	LoginLabels            []string           `json:"login_labels"`
	MaxHosts               int                `json:"max_hosts"`
	Providers              []IdentityProvider `json:"providers"`
}

var loadIdentityProviders = sync.OnceValue(func() IdentityProviders {
	var c IdentityProviders
	dec := json.NewDecoder(bytes.NewReader(identityProvidersJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("identity_providers.json: " + err.Error())
	}
	if !strings.HasPrefix(c.OIDCPath, "/") || !strings.HasPrefix(c.FederationMetadataPath, "/") ||
		len(c.LoginLabels) == 0 || c.MaxHosts <= 0 || len(c.Providers) == 0 {
		panic("identity_providers.json: oidc_path, federation_metadata_path, login_labels, max_hosts and " +
			"providers are required")
	}
	for _, p := range c.Providers {
		if p.Name == "" || len(p.Suffixes) == 0 || p.Source == "" || (p.TenantType == "") != (p.TenantPath == "") {
			panic("identity_providers.json: provider " + p.Name + " needs suffixes and a source, and a " +
				"tenant_type only with a tenant_path")
		}
	}
	return c
})

// IdentityProviderCatalog returns the identity provider catalog.
func IdentityProviderCatalog() IdentityProviders { return loadIdentityProviders() }

// IdentityProviderFor returns the provider whose tenant host host is.
func IdentityProviderFor(host string) (IdentityProvider, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, p := range loadIdentityProviders().Providers {
		for _, s := range p.Suffixes {
			if host == s || strings.HasSuffix(host, "."+s) {
				return p, true
			}
		}
	}
	return IdentityProvider{}, false
}

// IsLoginLabel reports whether label is a first label a sign-in host uses.
func IsLoginLabel(label string) bool {
	label = strings.ToLower(label)
	for _, l := range loadIdentityProviders().LoginLabels {
		if l == label {
			return true
		}
	}
	return false
}
