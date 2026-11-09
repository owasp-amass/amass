// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// CollectionPlan is a proposal, never permission. Its ID is a deterministic
// confirmation ID derived from the scope: anyone who knows the scope can
// compute it, so it confirms that the operator reviewed this exact scope but
// is not a secret or an authorization credential. Authorization comes from
// who may run the collect command. A model must not be able to launch
// discovery by calling a read-only graph tool; no tool exposes collection.
type CollectionPlan struct {
	ID               string        `json:"id,omitempty"`
	Target           AssetSelector `json:"target"`
	Status           string        `json:"status"`
	ScopeType        string        `json:"scope_type,omitempty"`
	ScopeValue       string        `json:"scope_value,omitempty"`
	Methods          []string      `json:"methods,omitempty"`
	RequiresApproval bool          `json:"requires_approval"`
	Reason           string        `json:"reason,omitempty"`
}

var collectionDNSLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// PlanCollection does not touch the Internet or Asset Database. Direct
// enumeration currently supports precisely specified FQDN, IP, netblock and
// ASN targets. Other OAM asset types require more specialized adapters.
func PlanCollection(target AssetSelector) CollectionPlan {
	plan := CollectionPlan{Target: target, Status: "unsupported", RequiresApproval: true}
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
			if !collectionDNSLabel.MatchString(label) {
				plan.Reason = "invalid DNS label"
				return plan
			}
		}
		plan.ScopeType = "domain"
		plan.ScopeValue = value
	case target.Type == "IPAddress" && target.Field == "address":
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
			plan.Reason = "only valid public unicast IPs are supported for collection"
			return plan
		}
		plan.ScopeType = "ip"
		plan.ScopeValue = addr.Unmap().String()
	case target.Type == "Netblock" && target.Field == "cidr":
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.IsValid() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
			plan.Reason = "only public CIDR ranges are supported for collection"
			return plan
		}
		plan.ScopeType = "cidr"
		plan.ScopeValue = prefix.Masked().String()
	case target.Type == "AutonomousSystem" && target.Field == "number":
		asn, err := strconv.ParseUint(value, 10, 32)
		if err != nil || asn == 0 {
			plan.Reason = "invalid autonomous system number"
			return plan
		}
		plan.ScopeType = "asn"
		plan.ScopeValue = fmt.Sprint(asn)
	default:
		plan.Reason = "this OAM selector has no approved direct enumeration adapter"
		return plan
	}
	plan.Methods = []string{"amass-engine-passive"}
	plan.Status = "approval_required"
	sum := sha256.Sum256([]byte("amass-ai-collect-v1\x00" + plan.ScopeType + "\x00" + plan.ScopeValue + "\x00passive"))
	plan.ID = hex.EncodeToString(sum[:12])
	plan.Reason = "Passive collection of this exact target only; unrelated or newly discovered targets are not separately authorized."
	return plan
}
