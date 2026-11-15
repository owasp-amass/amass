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
// plan's scope and mode, and returns the asset that seeds the session. No
// inherited scope, seed names or expansion survive; data source settings,
// resolvers and word lists do. Active mode keeps the configured ports.
func Configure(cfg *config.Config, plan Plan) (oam.Asset, error) {
	if cfg == nil {
		return nil, errors.New("collection configuration is required")
	}
	if plan.Status != StatusApprovalRequired || plan.ID == "" ||
		plan.ID != PlanID(plan.ScopeType, plan.ScopeValue, plan.Mode) {
		return nil, errors.New("not an approvable collection plan: " + plan.Reason)
	}

	ports := slices.Clone(config.DefaultPorts)
	if plan.Mode == Active && cfg.Scope != nil && len(cfg.Scope.Ports) > 0 {
		ports = slices.Clone(cfg.Scope.Ports)
	}

	cfg.Scope = &config.Scope{Ports: ports}
	cfg.Seed = cfg.Scope
	cfg.ProvidedNames = nil
	cfg.Rigid = true
	cfg.Recursive = false
	cfg.Passive = plan.Mode == Passive
	cfg.Active = plan.Mode == Active
	cfg.BruteForcing = plan.Mode == Active
	cfg.Alterations = plan.Mode == Active

	switch plan.ScopeType {
	case "domain":
		cfg.AddDomain(plan.ScopeValue)
		if len(cfg.Scope.Domains) != 1 || cfg.Scope.Domains[0] != plan.ScopeValue {
			return nil, errors.New("failed to set exact FQDN scope")
		}

		return oamdns.FQDN{Name: plan.ScopeValue}, nil
	case "ip":
		addr, err := netip.ParseAddr(plan.ScopeValue)
		ip := net.ParseIP(plan.ScopeValue)
		if err != nil || ip == nil {
			return nil, errors.New("invalid approved IP")
		}

		cfg.Scope.Addresses = []net.IP{ip}
		return oamnet.IPAddress{Address: addr, Type: ipKind(addr)}, nil
	case "cidr":
		prefix, err := netip.ParsePrefix(plan.ScopeValue)
		_, cidr, cerr := net.ParseCIDR(plan.ScopeValue)
		if err != nil || cerr != nil {
			return nil, errors.New("invalid approved CIDR")
		}

		cfg.Scope.CIDRs = []*net.IPNet{cidr}
		return oamnet.Netblock{CIDR: prefix, Type: ipKind(prefix.Addr())}, nil
	case "asn":
		num, err := strconv.Atoi(plan.ScopeValue)
		if err != nil || num <= 0 {
			return nil, errors.New("invalid approved ASN")
		}

		cfg.Scope.ASNs = []int{num}
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
