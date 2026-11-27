// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	lenscli "github.com/owasp-amass/amass/v5/internal/lens/cli"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// planArgs are the plan options the planning, starting and watching tools
// share, apart from the targets a call adds.
type planArgs struct {
	Expand         bool
	BruteForce     bool `json:"brute_force"`
	Alterations    bool
	Interface      string
	ActiveRoute    string `json:"active_route"`
	ActiveUDPRoute string `json:"active_udp_route"`
}

func (a planArgs) options() collect.Options {
	return collect.Options{Expand: a.Expand, BruteForce: a.BruteForce, Alterations: a.Alterations,
		Interface: a.Interface, ActiveRoute: a.ActiveRoute, ActiveUDPRoute: a.ActiveUDPRoute}
}

// planMode reads a mode as a user writes it; passive when none is given.
func planMode(mode string) collect.Mode {
	if m := collect.Mode(strings.ToLower(strings.TrimSpace(mode))); m != "" {
		return m
	}
	return collect.Passive
}

// planFor reads a target as a user writes it.
func planFor(target, mode string, also []string, opts collect.Options) collect.Plan {
	for _, a := range also {
		opts.Also = append(opts.Also, selectorFor(a))
	}

	return collect.NewPlanWith(selectorFor(target), planMode(mode), opts)
}

// oneSeed requires exactly one of target, phone or address: a request pivots
// from a phone or an address, or names a direct target, never more than one.
func oneSeed(target, phone, address string) error {
	n := 0
	for _, v := range []string{target, phone, address} {
		if strings.TrimSpace(v) != "" {
			n++
		}
	}
	if n == 0 {
		return errors.New("give a target, a phone or an address")
	}
	if n > 1 {
		return errors.New("give only one of target, phone or address")
	}
	return nil
}

// enumerationPlan builds the plan for a plan_enumeration or start_enumeration
// request: a direct target plan, or, when a phone or address is given, the
// pivot plan that resolves the seed to organizations and enumerates their
// registered domains.
func enumerationPlan(ctx context.Context, runner ai.ToolRunner, target, phone, address, mode string,
	also []string, opts collect.Options) (collect.Plan, error) {
	if sel, ok := pivotSelector(phone, address); ok {
		for _, a := range also {
			opts.Also = append(opts.Also, selectorFor(a))
		}
		return pivotPlan(ctx, runner, sel, planMode(mode), opts)
	}
	return planFor(target, mode, also, opts), nil
}

// pivotSelector returns the OAM selector for a phone or address seed, and
// whether the request is a pivot at all.
func pivotSelector(phone, address string) (graph.AssetSelector, bool) {
	switch {
	case strings.TrimSpace(phone) != "":
		// Normalize to E.164 so the warm lookup matches the stored Phone.
		return graph.AssetSelector{Type: "Phone", Field: "e164", Value: collect.NormalizePhone(phone)}, true
	case strings.TrimSpace(address) != "":
		return graph.AssetSelector{Type: "StreetAddress", Field: "address", Value: strings.TrimSpace(address)}, true
	}
	return graph.AssetSelector{}, false
}

// pivotPlan resolves a phone or address seed to the organizations tied to it
// and the domains they control, and returns a plan that enumerates those
// domains, with the resolution attached so the user approves a concrete scope.
// It never enumerates the phone or address itself. A shared address, or a seed
// that resolves to no domains, yields a non-approvable plan that still lists
// what was found so the user can choose a target.
func pivotPlan(ctx context.Context, runner ai.ToolRunner, seed graph.AssetSelector, mode collect.Mode,
	opts collect.Options) (collect.Plan, error) {
	if runner.Graph == nil || runner.Catalog == nil {
		return collect.Plan{}, errors.New("this server has no database to resolve a phone or address from")
	}
	resolver, ok := runner.Graph.(graph.AssetResolver)
	if !ok {
		return collect.Plan{}, errors.New("this database cannot resolve a phone or address")
	}

	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	res, err := resolver.ResolveAsset(rctx, seed, 1)
	if err != nil || len(res.Candidates) == 0 {
		// Cold: the seed is not in the database yet. Seed a passive resolution
		// pass from the phone or address itself — its reverse collector
		// resolves the organizations tied to it and their domains — so planning
		// again afterward enumerates the domains found. The pass is passive
		// whatever mode was asked: active enumeration waits for the re-plan,
		// where the resolved domains are shown first.
		rplan := collect.NewPlanWith(seed, collect.Passive,
			collect.Options{Expand: opts.Expand, Interface: opts.Interface})
		if rplan.Status != collect.StatusApprovalRequired {
			return rplan, nil
		}
		rplan.Pivot = &collect.PivotSeed{SeedType: seed.Type, SeedValue: strings.TrimSpace(seed.Value)}
		rplan.Effects = fmt.Sprintf("Resolves the organizations tied to this %s and collects their registered "+
			"domains from data sources. No hosts are probed. When it finishes, plan again from the same %s to "+
			"review the organizations and domains found and enumerate them.", strings.ToLower(seed.Type),
			strings.ToLower(seed.Type))
		return rplan, nil
	}

	resolution, err := lens.ResolveSeedPivot(rctx, runner.Graph, runner.Catalog, res.Candidates[0].Asset,
		lens.LensLimits{})
	if err != nil {
		return collect.Plan{}, err
	}

	pivot := &collect.PivotSeed{SeedType: resolution.SeedType, SeedValue: resolution.SeedValue,
		SharedAddress: resolution.SharedAddress}
	for _, o := range resolution.Organizations {
		pivot.Organizations = append(pivot.Organizations,
			collect.PivotSeedOrg{Name: o.Name, Domains: o.Domains, Principal: o.Principal})
	}

	switch {
	case resolution.SharedAddress:
		return collect.Plan{Status: collect.StatusUnsupported, RequiresApproval: true, Pivot: pivot,
			Reason: fmt.Sprintf("the address resolves to %d organizations: it is a shared or registered-agent "+
				"address, so it is not enumerated automatically. Name a specific organization's domain to "+
				"enumerate.", len(resolution.Organizations))}, nil
	case len(resolution.Domains) == 0:
		return collect.Plan{Status: collect.StatusUnsupported, RequiresApproval: true, Pivot: pivot,
			Reason: fmt.Sprintf("resolved %d organization(s) from this %s but no registered domains yet; "+
				"enumerate one of their known domains first", len(resolution.Organizations),
				strings.ToLower(seed.Type))}, nil
	}

	// Enumerate the resolved domains: the first as the target, the rest in also,
	// alongside any targets the caller added.
	o := opts
	for _, d := range resolution.Domains[1:] {
		o.Also = append(o.Also, selectorFor(d))
	}
	plan := collect.NewPlanWith(selectorFor(resolution.Domains[0]), mode, o)
	plan.Pivot = pivot
	return plan, nil
}

// pivotApprovalText describes, for the approval prompt, the seed a pivot plan
// resolved from and the organizations and domains it will enumerate.
func pivotApprovalText(p *collect.PivotSeed) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Resolved from %s %s:\n", strings.ToLower(p.SeedType), p.SeedValue)
	for _, o := range p.Organizations {
		name := o.Name
		if o.Principal {
			name += " (principal address)"
		}
		if len(o.Domains) > 0 {
			fmt.Fprintf(&b, "  - %s: %s\n", name, strings.Join(o.Domains, ", "))
		} else {
			fmt.Fprintf(&b, "  - %s\n", name)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// selectorFor reads a target as a domain, an IP address, a CIDR range or an
// AS number (AS15169 or 15169).
func selectorFor(target string) graph.AssetSelector {
	target = strings.TrimSpace(target)
	switch {
	case strings.Contains(target, "/"):
		return graph.AssetSelector{Type: "Netblock", Field: "cidr", Value: target}
	case asNumber.MatchString(target):
		return graph.AssetSelector{Type: "AutonomousSystem", Field: "number",
			Value: asNumber.FindStringSubmatch(target)[1]}
	}
	if _, err := netip.ParseAddr(target); err == nil {
		return graph.AssetSelector{Type: "IPAddress", Field: "address", Value: target}
	}

	return graph.AssetSelector{Type: "FQDN", Field: "name", Value: target}
}

// foundSince reports what was first stored under a finished run's target
// since the run started, as the changes lens computes it.
func foundSince(ctx context.Context, runner ai.ToolRunner, run collect.Run) any {
	resolver, ok := runner.Graph.(graph.AssetResolver)
	if !ok || run.Plan.Target.Type == "" {
		return "the database cannot look up the target"
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	sel := graph.AssetSelector{Type: run.Plan.Target.Type, Field: run.Plan.Target.Field, Value: run.Plan.ScopeValue}
	res, err := resolver.ResolveAsset(ctx, sel, 1)
	if err != nil || len(res.Candidates) == 0 {
		return "the target is not in the database yet"
	}

	report, err := lens.FindChanges(ctx, runner.Graph, runner.Catalog, res.Candidates[0].Asset, run.StartedAt,
		lens.LensLimits{})
	if err != nil {
		return "the changes lens could not run: " + err.Error()
	}

	return lens.FormatChangesReport(report)
}

// Bounds of a watch_decisions call: long enough to save the assistant most
// polls, short enough to stay under MCP clients' request timeouts.
const (
	defaultDecisionWait = 25
	maxDecisionWait     = 50
)

// decisionPoll is how often a waiting watch_decisions call checks the journal;
// a check that finds nothing appended costs one stat.
var decisionPoll = time.Second

// watchDecisions waits until the review journal records a new pending proposal
// or an AI-applied change after cursor, or until wait passes, and returns the
// new items and the next cursor. Without a cursor it returns at once with the
// cursor for the journal's end.
func watchDecisions(ctx context.Context, journal *review.Journal, cursor string, wait time.Duration,
	exists lenscli.EntityExists) (*mcp.CallToolResult, error) {
	deadline := time.Now().Add(wait)
	for {
		ch, err := lenscli.DecisionsSince(journal, cursor)
		if err != nil {
			return nil, err
		}
		if cursor == "" {
			// Start from now. What is already pending or applied is what
			// enumeration_status counts and list_proposals lists.
			return jsonResult(lenscli.DecisionChanges{Items: []lenscli.DecisionItem{}, Cursor: ch.Cursor}), nil
		}
		// Items about assets no longer stored (left from a database since
		// wiped) cannot be decided, so they are not announced.
		ch.Items = slices.DeleteFunc(ch.Items, func(d lenscli.DecisionItem) bool { return !d.Live(exists) })
		if len(ch.Items) > 0 || ch.Reset || !time.Now().Before(deadline) {
			if ch.Items == nil {
				ch.Items = []lenscli.DecisionItem{}
			}

			return jsonResult(ch), nil
		}

		// Lines that were not decisions move the cursor on.
		cursor = ch.Cursor
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(min(decisionPoll, time.Until(deadline))):
		}
	}
}
