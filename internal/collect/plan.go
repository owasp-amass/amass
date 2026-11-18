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
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/nyaruka/phonenumbers"
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
	Also             []ScopeEntry        `json:"also,omitempty"`
	Expand           bool                `json:"expand,omitempty"`
	BruteForce       bool                `json:"brute_force,omitempty"`
	Alterations      bool                `json:"alterations,omitempty"`
	Methods          []string            `json:"methods,omitempty"`
	Effects          string              `json:"effects,omitempty"`
	RequiresApproval bool                `json:"requires_approval"`
	Reason           string              `json:"reason,omitempty"`
	// Pivot records the phone or address this plan resolved from, when it was
	// reached by a seed pivot rather than named directly. Nil for a direct
	// target plan.
	Pivot *PivotSeed `json:"pivot,omitempty"`
}

// ScopeEntry is a target a plan puts in scope beside its own: a domain, an
// IP address, a CIDR range or an autonomous system.
type ScopeEntry struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// PivotSeed records that a plan was reached by resolving a phone number or a
// street address to the organizations tied to it and the domains they control.
// It travels on the plan so the approver sees exactly what the seed resolved to
// before any enumeration runs: the pivot never enumerates a phone or address
// directly, only the registered domains it resolved to.
type PivotSeed struct {
	SeedType      string         `json:"seed_type"`
	SeedValue     string         `json:"seed_value"`
	Organizations []PivotSeedOrg `json:"organizations,omitempty"`
	// SharedAddress marks a registered-agent or shared-building address: its
	// organizations are listed for review and the plan is not approvable, so a
	// shared address is never enumerated without the user naming the orgs.
	SharedAddress bool `json:"shared_address,omitempty"`
}

// PivotSeedOrg is one organization a seed resolved to, with the domains that
// would be enumerated and whether the tie is the organization's principal
// address.
type PivotSeedOrg struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains,omitempty"`
	Principal bool     `json:"principal,omitempty"`
}

// Options widen a plan beyond its one target.
type Options struct {
	// Also lists more targets in scope, collected in the same run.
	Also []graph.AssetSelector
	// Expand lets the engine add to the scope, while the run collects, the
	// domains, netblocks and autonomous systems it attributes to the
	// targets' organization (as amass enum does without -rigid).
	Expand bool
	// BruteForce turns on DNS brute forcing (as amass enum does with -brute).
	// It is off unless requested: brute forcing is never implied by active
	// mode, so an active run does not guess names unless asked.
	BruteForce bool
	// Alterations turns on name alterations (as amass enum does with -alts).
	// Like brute forcing it is off unless requested.
	Alterations bool
}

// MaxAlso is how many targets a plan may add beside its own.
const MaxAlso = 25

// Plan statuses.
const (
	StatusApprovalRequired = "approval_required"
	StatusUnsupported      = "unsupported"
)

var dnsLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// NewPlan computes the plan for collecting exactly target in mode. It
// touches neither the Internet nor the Asset Database. Exactly specified
// FQDN, IP address, netblock and autonomous system targets are supported.
func NewPlan(target graph.AssetSelector, mode Mode) Plan {
	return NewPlanWith(target, mode, Options{})
}

// NewPlanWith computes the plan for collecting target, and the targets
// opts adds, in mode. Each added target meets the same rules as target.
func NewPlanWith(target graph.AssetSelector, mode Mode, opts Options) Plan {
	plan := Plan{Target: target, Status: StatusUnsupported, RequiresApproval: true}
	if mode != Passive && mode != Active {
		plan.Reason = fmt.Sprintf("mode must be %q or %q", Passive, Active)
		return plan
	}

	typ, value, reason := scopeOf(target, mode)
	if reason != "" {
		plan.Reason = reason
		return plan
	}
	if len(opts.Also) > MaxAlso {
		plan.Reason = fmt.Sprintf("a plan adds at most %d targets", MaxAlso)
		return plan
	}

	seen := map[ScopeEntry]bool{{Type: typ, Value: value}: true}
	for _, sel := range opts.Also {
		t, v, reason := scopeOf(sel, mode)
		if reason != "" {
			plan.Reason = fmt.Sprintf("%s: %s", strings.TrimSpace(sel.Value), reason)
			return plan
		}

		if e := (ScopeEntry{Type: t, Value: v}); !seen[e] {
			seen[e] = true
			plan.Also = append(plan.Also, e)
		}
	}

	slices.SortFunc(plan.Also, func(a, b ScopeEntry) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.Value, b.Value))
	})

	plan.ScopeType, plan.ScopeValue = typ, value
	plan.Expand = opts.Expand
	plan.BruteForce = mode == Active && opts.BruteForce
	plan.Alterations = mode == Active && opts.Alterations
	plan.Mode = mode
	plan.Status = StatusApprovalRequired
	plan.ID = plan.expectedID()

	what := "this exact target"
	if len(plan.Also) > 0 {
		what = "these exact targets"
	}
	if mode == Passive {
		plan.Methods = []string{"amass-engine-passive"}
		plan.Effects = "Queries third-party data sources and public records about the targets. Their own hosts " +
			"are contacted only by ordinary DNS resolution of the names found."
		plan.Reason = "Passive collection of " + what + " only; unrelated or newly discovered targets are not " +
			"separately authorized."
	} else {
		// Brute forcing and name alterations are never implied by active mode;
		// they are added only when requested, so an active run does not guess
		// names unless asked.
		plan.Methods = []string{"amass-engine-passive"}
		if plan.BruteForce {
			plan.Methods = append(plan.Methods, "dns-brute-force")
		}
		if plan.Alterations {
			plan.Methods = append(plan.Methods, "name-alterations")
		}
		plan.Methods = append(plan.Methods, "zone-transfer", "certificate-and-service-probes")

		plan.Effects = "In addition to passive collection, attempts zone transfers from the targets' name " +
			"servers, and connects to the targets' hosts on the configured ports to read certificates and " +
			"service banners."
		if guessed := namesGuessed(plan.BruteForce, plan.Alterations); guessed != "" {
			plan.Effects += " It also sends DNS queries for " + guessed + "."
		}
		plan.Effects += " Run only against systems you are authorized to test."
		plan.Reason = "Active collection of " + what + " only; the scope is not expanded to newly discovered " +
			"domains or networks."
	}
	if plan.Expand {
		plan.Methods = append(plan.Methods, "scope-expansion")
		plan.Effects += " Scope expansion is allowed: domains, netblocks and autonomous systems the engine " +
			"attributes to the targets' organization while it runs join the scope and are collected the same way"
		if mode == Active {
			plan.Effects += ", their hosts probed too"
		}

		plan.Effects += "."
		plan.Reason = "Collection of " + what + " and of what the engine attributes to their organization while " +
			"it runs, so the run may reach domains and networks not listed here."
	}

	return plan
}

// namesGuessed describes the name-guessing an active plan does, or "" when it
// does none.
func namesGuessed(brute, alts bool) string {
	switch {
	case brute && alts:
		return "guessed and altered names"
	case brute:
		return "guessed names"
	case alts:
		return "altered names"
	default:
		return ""
	}
}

// scopeOf validates one target for collection in mode and returns its scope
// type and canonical value, or the reason it cannot be collected.
func scopeOf(target graph.AssetSelector, mode Mode) (string, string, string) {
	value := strings.TrimSpace(target.Value)
	if target.EntityID != "" || value == "" {
		return "", "", "an exact field/value identifier is required for collection"
	}

	switch {
	case target.Type == "FQDN" && target.Field == "name":
		value = strings.ToLower(strings.TrimSuffix(value, "."))
		if len(value) > 253 || !strings.Contains(value, ".") || strings.Contains(value, "..") {
			return "", "", "invalid FQDN"
		}
		for _, label := range strings.Split(value, ".") {
			if !dnsLabel.MatchString(label) {
				return "", "", "invalid DNS label"
			}
		}

		return "domain", value, ""
	case target.Type == "IPAddress" && target.Field == "address":
		addr, err := netip.ParseAddr(value)
		if err != nil || !public(addr) {
			return "", "", "only valid public unicast IPs are supported for collection"
		}

		return "ip", addr.Unmap().String(), ""
	case target.Type == "Netblock" && target.Field == "cidr":
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.IsValid() || !public(prefix.Addr()) {
			return "", "", "only public CIDR ranges are supported for collection"
		}

		prefix = prefix.Masked()
		if mode == Active && ((prefix.Addr().Is4() && prefix.Bits() < maxActiveIPv4Prefix) ||
			(prefix.Addr().Is6() && prefix.Bits() < maxActiveIPv6Prefix)) {
			return "", "", fmt.Sprintf("active collection covers at most a /%d IPv4 or /%d IPv6 range; split "+
				"the range or collect it passively", maxActiveIPv4Prefix, maxActiveIPv6Prefix)
		}

		return "cidr", prefix.String(), ""
	case target.Type == "AutonomousSystem" && target.Field == "number":
		asn, err := strconv.ParseUint(value, 10, 32)
		if err != nil || asn == 0 {
			return "", "", "invalid autonomous system number"
		}

		return "asn", fmt.Sprint(asn), ""
	case target.Type == "Phone" && target.Field == "e164":
		// A phone seed resolves the organizations tied to the number and their
		// domains; it probes no hosts, so it is collected passively only.
		if mode == Active {
			return "", "", "a phone number resolves organizations and is collected passively; it cannot be an " +
				"active target. Enumerate the resolved domains actively instead."
		}
		// Normalize to E.164 so the seed matches the stored Phone, whose key is
		// its E.164 form, and so the reverse lookup's digit match is reliable.
		e164 := NormalizePhone(value)
		if countDigits(e164) < 7 {
			return "", "", "invalid phone number"
		}

		return "phone", e164, ""
	case target.Type == "Location" && target.Field == "address":
		// Likewise an address resolves the organizations at it; passive only.
		if mode == Active {
			return "", "", "an address resolves organizations and is collected passively; it cannot be an " +
				"active target. Enumerate the resolved domains actively instead."
		}
		if value == "" {
			return "", "", "invalid address"
		}

		return "location", value, ""
	}

	return "", "", "this OAM selector has no approved direct enumeration adapter"
}

// NormalizePhone returns raw as an E.164 number when it parses as a valid
// number, so a phone seed a user types in any format ("+1 315-228-1000",
// "+13152281000") matches the stored Phone, whose key is its E.164 form. A
// number that cannot be parsed to E.164 — for example a bare national number
// with no country code — is returned trimmed and unchanged, so an exact stored
// value can still match.
func NormalizePhone(raw string) string {
	s := strings.TrimSpace(raw)
	if num, err := phonenumbers.Parse(s, ""); err == nil && phonenumbers.IsValidNumber(num) {
		return phonenumbers.Format(num, phonenumbers.E164)
	}
	return s
}

// countDigits returns how many decimal digits s contains.
func countDigits(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n
}

// PlanID is the confirmation ID of a scope and mode. The passive form is
// the one earlier releases used, so existing approvals keep working.
func PlanID(scopeType, scopeValue string, mode Mode) string {
	sum := sha256.Sum256([]byte("amass-ai-collect-v1\x00" + scopeType + "\x00" + scopeValue + "\x00" + string(mode)))
	return hex.EncodeToString(sum[:12])
}

// expectedID is the confirmation ID of the plan's whole scope: PlanID for
// one exact target, as before, and otherwise one that also covers the added
// targets and scope expansion.
func (p Plan) expectedID() string {
	if len(p.Also) == 0 && !p.Expand {
		return PlanID(p.ScopeType, p.ScopeValue, p.Mode)
	}

	var b strings.Builder
	b.WriteString("amass-ai-collect-v2\x00" + p.ScopeType + "\x00" + p.ScopeValue + "\x00" + string(p.Mode))
	for _, e := range p.Also {
		b.WriteString("\x00" + e.Type + "\x00" + e.Value)
	}
	if p.Expand {
		b.WriteString("\x00expand")
	}

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:12])
}

// Approvable reports whether the plan can be approved: it was computed as
// approvable and its ID matches its scope, so its scope was not changed
// after it was shown.
func (p Plan) Approvable() bool {
	return p.Status == StatusApprovalRequired && p.ID != "" && p.ID == p.expectedID()
}

func public(addr netip.Addr) bool {
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() && !addr.IsUnspecified()
}

// Summary is a one-line description of a plan for an approval prompt.
func (p Plan) Summary() string {
	out := fmt.Sprintf("%s enumeration of %s %s", strings.ToUpper(string(p.Mode)), p.ScopeType, p.ScopeValue)
	if len(p.Also) > 0 {
		parts := make([]string, 0, len(p.Also))
		for _, e := range p.Also {
			parts = append(parts, e.Type+" "+e.Value)
		}

		out += " with " + strings.Join(parts, ", ")
	}
	if p.Expand {
		out += ", allowing scope expansion"
	}

	return out
}
