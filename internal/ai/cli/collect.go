// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/owasp-amass/amass/v5/config"
	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
	"github.com/owasp-amass/amass/v5/internal/ai"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type collectionResponse struct {
	Status       string            `json:"status"`
	Plan         ai.CollectionPlan `json:"plan"`
	SessionToken string            `json:"session_token,omitempty"`
}

// collectTarget is deliberately separate from model tools. Without the exact
// confirmation ID of the reviewed plan, neither an engine session nor an
// Internet request can be created. The ID is not a secret (see CollectionPlan). This phase starts one passive session and returns its token;
// session monitoring and automatic query resumption are future integrations.
func collectTarget(ctx context.Context, cfg *config.Config, plan ai.CollectionPlan, approved string, execute bool, out io.Writer) error {
	response := collectionResponse{Status: plan.Status, Plan: plan}
	if !execute {
		return json.NewEncoder(out).Encode(response)
	}
	if plan.Status != "approval_required" || plan.ID == "" {
		return fmt.Errorf("unsupported collection target: %s", plan.Reason)
	}
	if approved == "" || approved != plan.ID {
		return errors.New("collection requires -approve-collection matching the exact plan id")
	}
	if cfg == nil {
		return errors.New("collection configuration is required")
	}
	// No inherited scope, IPs, domains, seed names, active techniques, or
	// expansion are permitted. Only the approved scope becomes a session seed.
	cfg.Scope = &config.Scope{Ports: []int{80, 443}}
	cfg.Seed = cfg.Scope
	cfg.ProvidedNames = nil
	cfg.Active = false
	cfg.Passive = true
	cfg.BruteForcing = false
	cfg.Alterations = false
	cfg.Recursive = false
	cfg.Rigid = true
	var asset oam.Asset
	switch plan.ScopeType {
	case "domain":
		cfg.AddDomain(plan.ScopeValue)
		if len(cfg.Scope.Domains) != 1 || cfg.Scope.Domains[0] != plan.ScopeValue {
			return errors.New("failed to set exact FQDN scope")
		}
		asset = oamdns.FQDN{Name: plan.ScopeValue}
	case "ip":
		ip := net.ParseIP(plan.ScopeValue)
		addr, err := netip.ParseAddr(plan.ScopeValue)
		if err != nil || ip == nil {
			return errors.New("invalid approved IP")
		}
		cfg.Scope.Addresses = []net.IP{ip}
		kind := "IPv4"
		if addr.Is6() {
			kind = "IPv6"
		}
		asset = oamnet.IPAddress{Address: addr, Type: kind}
	case "cidr":
		_, cidr, err := net.ParseCIDR(plan.ScopeValue)
		addr, perr := netip.ParsePrefix(plan.ScopeValue)
		if err != nil || perr != nil {
			return errors.New("invalid approved CIDR")
		}
		cfg.Scope.CIDRs = []*net.IPNet{cidr}
		kind := "IPv4"
		if addr.Addr().Is6() {
			kind = "IPv6"
		}
		asset = oamnet.Netblock{CIDR: addr, Type: kind}
	case "asn":
		num, err := strconv.Atoi(plan.ScopeValue)
		if err != nil || num <= 0 {
			return errors.New("invalid approved ASN")
		}
		cfg.Scope.ASNs = []int{num}
		asset = oamnet.AutonomousSystem{Number: num}
	default:
		return errors.New("unsupported collection scope type")
	}
	endpoint := "http://127.0.0.1:4000"
	if cfg.EngineAPI != nil && cfg.EngineAPI.URL != "" {
		endpoint = cfg.EngineAPI.URL
	}
	c, err := client.NewClient(endpoint)
	if err != nil {
		return err
	}
	defer c.Close()
	token, err := c.CreateSession(ctx, cfg)
	if err != nil {
		return fmt.Errorf("create approved collection session: %w", err)
	}
	// A seed failure must not leave an unapproved idle session behind.
	if _, err := c.CreateAsset(ctx, token, asset); err != nil {
		_ = c.TerminateSession(context.Background(), token)
		return fmt.Errorf("seed approved collection session: %w", err)
	}
	response.Status = "started"
	response.SessionToken = token.String()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(response)
}
