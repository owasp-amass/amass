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
	cfg.Rigid = !plan.Expand
	cfg.Recursive = false
	cfg.Passive = plan.Mode == Passive
	cfg.Active = plan.Mode == Active
	cfg.BruteForcing = plan.Mode == Active
	cfg.Alterations = plan.Mode == Active

	entries := append([]ScopeEntry{{Type: plan.ScopeType, Value: plan.ScopeValue}}, plan.Also...)
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

// addScope puts one approved target in cfg's scope and returns its asset.
func addScope(cfg *config.Config, e ScopeEntry) (oam.Asset, error) {
	switch e.Type {
	case "domain":
		n := len(cfg.Scope.Domains)
		cfg.AddDomain(e.Value)
		if len(cfg.Scope.Domains) != n+1 || cfg.Scope.Domains[n] != e.Value {
			return nil, errors.New("failed to set exact FQDN scope")
		}

		return oamdns.FQDN{Name: e.Value}, nil
	case "ip":
		addr, err := netip.ParseAddr(e.Value)
		ip := net.ParseIP(e.Value)
		if err != nil || ip == nil {
			return nil, errors.New("invalid approved IP")
		}

		cfg.Scope.Addresses = append(cfg.Scope.Addresses, ip)
		return oamnet.IPAddress{Address: addr, Type: ipKind(addr)}, nil
	case "cidr":
		prefix, err := netip.ParsePrefix(e.Value)
		_, cidr, cerr := net.ParseCIDR(e.Value)
		if err != nil || cerr != nil {
			return nil, errors.New("invalid approved CIDR")
		}

		cfg.Scope.CIDRs = append(cfg.Scope.CIDRs, cidr)
		return oamnet.Netblock{CIDR: prefix, Type: ipKind(prefix.Addr())}, nil
	case "asn":
		num, err := strconv.Atoi(e.Value)
		if err != nil || num <= 0 {
			return nil, errors.New("invalid approved ASN")
		}

		cfg.Scope.ASNs = append(cfg.Scope.ASNs, num)
		return oamnet.AutonomousSystem{Number: num}, nil
	}

	return nil, errors.New("unsupported collection scope type")
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
