// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package collect

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"github.com/owasp-amass/amass/v5/config"
	oam "github.com/owasp-amass/open-asset-model"
	oamcontact "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// Configure narrows cfg, a freshly loaded configuration, to exactly the
// plan's scope and mode, and returns the asset of the plan's target. No
// inherited scope, seed names or expansion survive; data source settings,
// resolvers and word lists do. Active mode keeps the configured ports.
func Configure(cfg *config.Config, plan Plan) (oam.Asset, error) {
	assets, err := configure(cfg, plan)
	if err != nil {
		return nil, err
	}

	return assets[0], nil
}

// configure is Configure, returning the assets that seed the session: the
// plan's target first, then the targets the plan adds. The scope expands
// only when the plan allows it.
func configure(cfg *config.Config, plan Plan) ([]oam.Asset, error) {
	if cfg == nil {
		return nil, errors.New("collection configuration is required")
	}
	if !plan.Approvable() {
		return nil, errors.New("not an approvable collection plan: " + plan.Reason)
	}

	ports := slices.Clone(config.DefaultPorts)
	if plan.Mode == Active && cfg.Scope != nil && len(cfg.Scope.Ports) > 0 {
		ports = slices.Clone(cfg.Scope.Ports)
	}

	cfg.Scope = &config.Scope{Ports: ports}
	cfg.Seed = cfg.Scope
	cfg.ProvidedNames = nil
	// A plan approved without expansion is held to its exact scope: nothing
	// is admitted and nothing outside it is investigated. With expansion, the
	// configuration's own expansion policy applies.
	if !plan.Expand {
		cfg.ApplyStrictPolicy()
	}
	cfg.Recursive = false
	cfg.Passive = plan.Mode == Passive
	cfg.Active = plan.Mode == Active
	// Brute forcing and name alterations are opt-in, never implied by active
	// mode: they run only when the plan requested them.
	cfg.BruteForcing = plan.BruteForce
	cfg.Alterations = plan.Alterations
	// the plan's interface, when it names one, replaces the configuration's
	if plan.Interface != "" {
		cfg.Interface = plan.Interface
	}
	if plan.ActiveRoute != "" {
		cfg.ActiveRoute = plan.ActiveRoute
	}
	if plan.ActiveUDPRoute != "" {
		cfg.ActiveUDPRoute = plan.ActiveUDPRoute
	}

	entries := plan.Entries()
	assets := make([]oam.Asset, 0, len(entries))
	for _, e := range entries {
		a, err := addScope(cfg, e)
		if err != nil {
			return nil, err
		}

		assets = append(assets, a)
	}

	return assets, nil
}

// Entries returns the plan's scope: its own target first, then the targets it
// adds.
func (p Plan) Entries() []ScopeEntry {
	return append([]ScopeEntry{{Type: p.ScopeType, Value: p.ScopeValue}}, p.Also...)
}

// Asset returns the asset a scope entry names.
func (e ScopeEntry) Asset() (oam.Asset, error) {
	switch e.Type {
	case "domain":
		return oamdns.FQDN{Name: e.Value}, nil
	case "ip":
		addr, err := netip.ParseAddr(e.Value)
		if err != nil || net.ParseIP(e.Value) == nil {
			return nil, errors.New("invalid approved IP")
		}

		return oamnet.IPAddress{Address: addr, Type: ipKind(addr)}, nil
	case "cidr":
		prefix, err := netip.ParsePrefix(e.Value)
		if _, _, cerr := net.ParseCIDR(e.Value); err != nil || cerr != nil {
			return nil, errors.New("invalid approved CIDR")
		}

		return oamnet.Netblock{CIDR: prefix, Type: ipKind(prefix.Addr())}, nil
	case "asn":
		num, err := strconv.Atoi(e.Value)
		if err != nil || num <= 0 {
			return nil, errors.New("invalid approved ASN")
		}

		return oamnet.AutonomousSystem{Number: num}, nil
	case "phone":
		return oamcontact.Phone{E164: e.Value, Raw: e.Value}, nil
	case "street_address":
		return oamcontact.StreetAddress{Address: e.Value}, nil
	}

	return nil, errors.New("unsupported collection scope type")
}

// addScope puts one approved target in cfg's scope and returns its asset.
func addScope(cfg *config.Config, e ScopeEntry) (oam.Asset, error) {
	a, err := e.Asset()
	if err != nil {
		return nil, err
	}

	switch v := a.(type) {
	case oamdns.FQDN:
		n := len(cfg.Scope.Domains)
		cfg.AddDomain(e.Value)
		if len(cfg.Scope.Domains) != n+1 || cfg.Scope.Domains[n] != e.Value {
			return nil, errors.New("failed to set exact FQDN scope")
		}
	case oamnet.IPAddress:
		cfg.Scope.Addresses = append(cfg.Scope.Addresses, net.ParseIP(e.Value))
	case oamnet.Netblock:
		_, cidr, _ := net.ParseCIDR(e.Value)
		cfg.Scope.CIDRs = append(cfg.Scope.CIDRs, cidr)
	case oamnet.AutonomousSystem:
		cfg.Scope.ASNs = append(cfg.Scope.ASNs, v.Number)
	case oamcontact.Phone:
		cfg.Scope.Phones = append(cfg.Scope.Phones, e.Value)
	case oamcontact.StreetAddress:
		cfg.Scope.StreetAddresses = append(cfg.Scope.StreetAddresses, e.Value)
	}

	return a, nil
}

func ipKind(addr netip.Addr) string {
	if addr.Is6() {
		return "IPv6"
	}

	return "IPv4"
}

// EngineURL is the engine API a configuration names, or the default.
func EngineURL(cfg *config.Config) string {
	if cfg != nil && cfg.EngineAPI != nil && cfg.EngineAPI.URL != "" {
		return cfg.EngineAPI.URL
	}

	return "http://127.0.0.1:4000"
}
