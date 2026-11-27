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

//go:embed routing_registries.json
var routingRegistriesJSON []byte

// RoutingRegistries is where routing security records are read and which
// registry maintainers are ignored. Loaded from routing_registries.json; see
// that file's _about.
type RoutingRegistries struct {
	License             string   `json:"_license"`
	About               string   `json:"_about"`
	StatAPI             string   `json:"stat_api"`
	SourceApp           string   `json:"source_app"`
	IRRWhois            string   `json:"irr_whois"`
	RegistryMaintainers []string `json:"registry_maintainers"`
	MaxRoutes           int      `json:"max_routes"`
	MaxOrigins          int      `json:"max_origins"`
	Sources             []string `json:"sources"`
}

var loadRoutingRegistries = sync.OnceValue(func() RoutingRegistries {
	var c RoutingRegistries
	dec := json.NewDecoder(bytes.NewReader(routingRegistriesJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("routing_registries.json: " + err.Error())
	}
	if !strings.HasPrefix(c.StatAPI, "https://") || c.IRRWhois == "" || !strings.Contains(c.IRRWhois, ":") ||
		c.MaxRoutes <= 0 || c.MaxOrigins <= 0 || len(c.Sources) == 0 {
		panic("routing_registries.json: stat_api (https), irr_whois (host:port), max_routes, max_origins " +
			"and sources are required")
	}
	return c
})

// RoutingRegistryCatalog returns the routing registry catalog.
func RoutingRegistryCatalog() RoutingRegistries { return loadRoutingRegistries() }

// RegistryMaintainer reports whether a maintainer handle belongs to a
// registry rather than an operator.
func (c RoutingRegistries) RegistryMaintainer(handle string) bool {
	handle = strings.ToUpper(strings.TrimSpace(handle))
	for _, p := range c.RegistryMaintainers {
		if strings.HasPrefix(handle, strings.ToUpper(p)) {
			return true
		}
	}
	return false
}
