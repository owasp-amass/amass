// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package collect plans, starts and supervises enumeration sessions on the
// Amass engine for an exact, approved scope. It uses no model: plans are
// computed from the target alone, and starting one needs the plan's ID and
// whatever approval the caller requires (the CLI's flag, an MCP client's
// confirmation).
package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// Mode is how a session collects.
type Mode string

const (
	// Passive asks third-party data sources and public records only; the
	// target's own hosts are not contacted beyond ordinary DNS resolution.
	Passive Mode = "passive"
	// Active also brute forces and alters names, attempts zone transfers and
	// connects to the target's hosts to read certificates and services.
	Active Mode = "active"
)

// Active enumeration of a range larger than these prefixes is refused: it
// would probe more addresses than one approval should cover.
const (
	maxActiveIPv4Prefix = 16
	maxActiveIPv6Prefix = 48
)

// Plan is a proposal, never permission. Its ID is a deterministic
// confirmation ID derived from the scope and mode: anyone who knows them can
// compute it, so it confirms that the approver saw this exact scope but is
// not a secret or an authorization credential.
type Plan struct {
	ID               string              `json:"id,omitempty"`
	Target           graph.AssetSelector `json:"target"`
	Status           string              `json:"status"`
	Mode             Mode                `json:"mode,omitempty"`
	ScopeType        string              `json:"scope_type,omitempty"`
	ScopeValue       string              `json:"scope_value,omitempty"`
	Methods          []string            `json:"methods,omitempty"`
	Effects          string              `json:"effects,omitempty"`
	RequiresApproval bool                `json:"requires_approval"`
	Reason           string              `json:"reason,omitempty"`
}

// Plan statuses.
const (
	StatusApprovalRequired = "approval_required"
	StatusUnsupported      = "unsupported"
)

var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// NewPlan computes the plan for collecting target in mode. It touches
// neither the Internet nor the Asset Database. Exactly specified FQDN, IP
// address, netblock and autonomous system targets are supported.
func NewPlan(target graph.AssetSelector, mode Mode) Plan {
	plan := Plan{Target: target, Status: StatusUnsupported, RequiresApproval: true}
	if mode != Passive && mode != Active {
		plan.Reason = fmt.Sprintf("mode must be %q or %q", Passive, Active)
		return plan
	}

	value := strings.TrimSpace(target.Value)
	if target.EntityID != "" || value == "" {
		plan.Reason = "an exact field/value identifier is required for collection"
		return plan
	}

	switch {
	case target.Type == "FQDN" && target.Field == "name":
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		if len(value) > 253 || !strings.Contains(value, ".") || strings.Contains(value, "..") {
			plan.Reason = "invalid FQDN"
			return plan
		}
		for _, label := range strings.Split(value, ".") {
			if !dnsLabel.MatchString(label) {
				plan.Reason = "invalid DNS label"
				return plan
			}
		}
		plan.ScopeType, plan.ScopeValue = "domain", value
	case target.Type == "IPAddress" && target.Field == "address":
		addr, err := netip.ParseAddr(value)
		if err != nil || !public(addr) {
			plan.Reason = "only valid public unicast IPs are supported for collection"
			return plan
		}
		plan.ScopeType, plan.ScopeValue = "ip", addr.Unmap().String()
	case target.Type == "Netblock" && target.Field == "cidr":
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.IsValid() || !public(prefix.Addr()) {
			plan.Reason = "only public CIDR ranges are supported for collection"
			return plan
		}
		prefix = prefix.Masked()
		if mode == Active && ((prefix.Addr().Is4() && prefix.Bits() < maxActiveIPv4Prefix) ||
			(prefix.Addr().Is6() && prefix.Bits() < maxActiveIPv6Prefix)) {
			plan.Reason = fmt.Sprintf("active collection covers at most a /%d IPv4 or /%d IPv6 range; split the "+
				"range or collect it passively", maxActiveIPv4Prefix, maxActiveIPv6Prefix)
			return plan
		}
		plan.ScopeType, plan.ScopeValue = "cidr", prefix.String()
	case target.Type == "AutonomousSystem" && target.Field == "number":
		asn, err := strconv.ParseUint(value, 10, 32)
		if err != nil || asn == 0 {
			plan.Reason = "invalid autonomous system number"
			return plan
		}
		plan.ScopeType, plan.ScopeValue = "asn", fmt.Sprint(asn)
	default:
		plan.Reason = "this OAM selector has no approved direct enumeration adapter"
		return plan
	}

	plan.Mode = mode
	plan.Status = StatusApprovalRequired
	plan.ID = PlanID(plan.ScopeType, plan.ScopeValue, mode)
	if mode == Passive {
		plan.Methods = []string{"amass-engine-passive"}
		plan.Effects = "Queries third-party data sources and public records about this target. The target's own " +
			"hosts are contacted only by ordinary DNS resolution of the names found."
		plan.Reason = "Passive collection of this exact target only; unrelated or newly discovered targets are " +
			"not separately authorized."
	} else {
		plan.Methods = []string{"amass-engine-passive", "dns-brute-force", "name-alterations", "zone-transfer",
			"certificate-and-service-probes"}
		plan.Effects = "In addition to passive collection, sends DNS queries for guessed names, attempts zone " +
			"transfers from the target's name servers, and connects to the target's hosts on the configured " +
			"ports to read certificates and service banners. Run only against systems you are authorized to test."
		plan.Reason = "Active collection of this exact target only; the scope is not expanded to newly " +
			"discovered domains or networks."
	}
	return plan
}

// PlanID is the confirmation ID of a scope and mode. The passive form is
// the one earlier releases used, so existing approvals keep working.
func PlanID(scopeType, scopeValue string, mode Mode) string {
	sum := sha256.Sum256([]byte("amass-ai-collect-v1\x00" + scopeType + "\x00" + scopeValue + "\x00" + string(mode)))
	return hex.EncodeToString(sum[:12])
}

func public(addr netip.Addr) bool {
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && !addr.IsUnspecified()
}

// Summary is a one-line description of a plan for an approval prompt.
func (p Plan) Summary() string {
	return fmt.Sprintf("%s enumeration of %s %s", strings.ToUpper(string(p.Mode)), p.ScopeType, p.ScopeValue)
}
