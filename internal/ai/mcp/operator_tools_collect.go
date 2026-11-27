// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/collect"
	lenscli "github.com/owasp-amass/amass/v5/internal/lens/cli"
)

// collectionTools are the tools that plan, start, watch and stop enumerations.
func (t *operatorTools) collectionTools() {
	target := map[string]any{"type": "string",
		"description": "The exact target: a domain (example.com), an IP address, a CIDR range or an AS number (AS15169)"}
	mode := map[string]any{"type": "string", "enum": []string{string(collect.Passive), string(collect.Active)},
		"description": "passive (default) queries data sources only; active also probes the target's hosts"}
	also := map[string]any{"type": "array", "maxItems": collect.MaxAlso,
		"items": map[string]any{"type": "string"},
		"description": "More targets in scope for the same run, each a domain, an IP address, a CIDR range or an " +
			"AS number, such as the organization's own netblocks and AS"}
	expand := map[string]any{"type": "boolean",
		"description": "Allow scope expansion: domains, netblocks and ASes the engine attributes to the targets' " +
			"organization while it runs are collected too (default false: only the listed targets)"}
	bruteForce := map[string]any{"type": "boolean",
		"description": "Turn on DNS brute forcing: guess subdomain names from a wordlist (active mode only, " +
			"default false). Off unless the user asks for it; it greatly increases the work and the queries sent."}
	alterations := map[string]any{"type": "boolean",
		"description": "Turn on name alterations: permute discovered names to find more (active mode only, " +
			"default false). Off unless the user asks for it."}
	iface := map[string]any{"type": "string", "maxLength": 64,
		"description": "Network interface on the engine's host for the run's traffic: an interface name such as " +
			"eth0, or one of the host's IP addresses (default: the engine's own setting). Only when the user asks."}
	activeRoute := map[string]any{"type": "string", "maxLength": 256,
		"description": "Route for the run's active traffic (active mode only): an interface on the engine's host, " +
			"or a proxy URL such as socks5h://tor:9050 (socks5h, socks5 or http CONNECT). Active traffic never " +
			"falls back to a direct connection. Never include a password; that belongs in the configuration. " +
			"Only when the user asks."}
	activeUDPRoute := map[string]any{"type": "string", "maxLength": 64,
		"description": "Interface for active UDP when active_route is a proxy, which carries TCP only. Only when " +
			"the user asks."}
	phone := map[string]any{"type": "string",
		"description": "Pivot from a phone number instead of a target: resolve the organizations tied to it and " +
			"enumerate their registered domains. Give one of target, phone or address."}
	address := map[string]any{"type": "string",
		"description": "Pivot from a street address instead of a target: resolve the organizations at it and " +
			"enumerate their registered domains. A shared or registered-agent address is held for review, not " +
			"enumerated. Give one of target, phone or address."}
	op, runner := t.op, t.runner

	t.add(ToolPlanEnumeration, "Plan an Amass enumeration",
		"Show what an enumeration would do, without starting it: the scope (one target, any more targets in also, "+
			"and whether it may expand), the methods, their effects, and the plan_id that start_enumeration needs. "+
			"Instead of a target you may give a phone or address to pivot from: the plan then lists the "+
			"organizations the seed resolved to and enumerates their registered domains.",
		obj(nil, map[string]any{"target": target, "mode": mode, "also": also, "expand": expand,
			"brute_force": bruteForce, "alterations": alterations, "interface": iface, "active_route": activeRoute,
			"active_udp_route": activeUDPRoute, "phone": phone, "address": address}),
		readOnly(),
		func(ctx context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				Target string
				Mode   string
				Also   []string
				planArgs
				Phone   string
				Address string
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if err := oneSeed(a.Target, a.Phone, a.Address); err != nil {
				return nil, err
			}

			plan, err := enumerationPlan(ctx, runner, a.Target, a.Phone, a.Address, a.Mode, a.Also,
				a.options())
			if err != nil {
				return nil, err
			}
			if plan.Status != collect.StatusApprovalRequired {
				// A pivot that resolved organizations but cannot be enumerated
				// (a shared address, or no domains yet) still shows them, so the
				// user can pick a target; a direct target that is unsupported is
				// an error as before.
				if plan.Pivot != nil {
					return jsonResult(map[string]any{"plan": plan, "next": plan.Reason}), nil
				}
				return nil, errors.New("cannot enumerate this target: " + plan.Reason)
			}

			next := "Show the user the scope and effects, then call start_enumeration with the same target, " +
				"mode, also, expand, brute_force, alterations, interface and active routes, and this plan_id. The user " +
				"is asked to approve it."
			if plan.Pivot != nil {
				next = "Show the user the phone/address, the organizations it resolved to and the domains to be " +
					"enumerated, then call start_enumeration with the same phone or address, mode, expand, " +
					"brute_force, alterations, interface and active routes, and this plan_id. The user is asked to approve it."
			}
			return jsonResult(map[string]any{"plan": plan, "next": next}), nil
		})

	t.approveAction(ToolStartEnumeration, "Start an Amass enumeration",
		"Start the enumeration a plan_enumeration call described. Collects data from the Internet about the "+
			"target and stores it in the Asset Database; the user is asked to approve it first.",
		obj([]string{"plan_id"}, map[string]any{"target": target, "mode": mode, "also": also,
			"expand": expand, "brute_force": bruteForce, "alterations": alterations, "interface": iface,
			"active_route": activeRoute, "active_udp_route": activeUDPRoute, "phone": phone, "address": address,
			"plan_id": map[string]any{
				"type":        "string",
				"description": "The plan_id plan_enumeration returned",
			}}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (string,
			func(via string) (*mcp.CallToolResult, error), error) {
			var a struct {
				Target string
				Mode   string
				Also   []string
				planArgs
				Phone   string
				Address string
				PlanID  string `json:"plan_id"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return "", nil, err
			}
			if err := oneSeed(a.Target, a.Phone, a.Address); err != nil {
				return "", nil, err
			}
			if op.Collect == nil {
				return "", nil, errors.New("this server cannot start enumerations: no engine is configured")
			}

			plan, err := enumerationPlan(ctx, runner, a.Target, a.Phone, a.Address, a.Mode, a.Also,
				a.options())
			if err != nil {
				return "", nil, err
			}
			if plan.Status != collect.StatusApprovalRequired {
				return "", nil, errors.New("cannot enumerate this: " + plan.Reason)
			}
			if a.PlanID != plan.ID {
				return "", nil, errors.New("plan_id does not match this request; call plan_enumeration again and " +
					"show the user the new plan (a pivot's resolved domains can change as data is collected)")
			}

			msg := fmt.Sprintf("Start a %s?\n\n%s", plan.Summary(), plan.Effects)
			if plan.Pivot != nil {
				msg = fmt.Sprintf("Start a %s?\n\n%s\n\n%s", plan.Summary(), pivotApprovalText(plan.Pivot),
					plan.Effects)
			}
			return msg, func(via string) (*mcp.CallToolResult, error) {
				sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
				defer cancel()
				run, err := op.Collect.Start(sctx, plan, approver(req, via))
				if err != nil {
					return nil, err
				}

				next := "Check progress with enumeration_status; runs end on their own when the work is done."
				if run.Joined {
					next = "Another engine on the database was already enumerating this scope, so this run " +
						"joined its job (" + run.Job + ") and works under that job's configuration, sharing " +
						"its work. Tell the user. " + next
				}
				return jsonResult(map[string]any{"run": run, "next": next}), nil
			}, nil
		})

	t.add(ToolEnumerationStatus, "Amass enumeration status",
		"Show the enumerations this server started: state, progress and, for a finished run, what it found. "+
			"A run that joined another engine's enumeration of the same scope shows its job and joined, and its "+
			"progress is the whole job's. With run_id, a running run also lists the job's workers (engine "+
			"sessions): whether each is still there, its background work, the items it holds and did, and "+
			"modelCalls, the requests its main model was sent; model_calls is the job's total. "+
			"Without run_id, lists every run.",
		obj(nil, map[string]any{"run_id": map[string]any{"type": "string"}}), readOnly(),
		func(ctx context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				RunID string `json:"run_id"`
			}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &a); err != nil {
					return nil, err
				}
			}
			if op.Collect == nil {
				return nil, errors.New("no engine is configured")
			}
			if a.RunID == "" {
				return jsonResult(map[string]any{"runs": op.Collect.Runs()}), nil
			}

			run, ok := op.Collect.Get(a.RunID)
			if !ok {
				return nil, fmt.Errorf("no enumeration run %s", a.RunID)
			}

			out := map[string]any{"run": run}
			if run.Finished() && runner.Graph != nil {
				out["found"] = foundSince(ctx, runner, run)
			}
			// the engine sessions sharing the run's job, when engines share work
			if ws, err := op.Collect.Workers(ctx, run.ID); err == nil && len(ws) > 0 {
				var calls int64
				for _, w := range ws {
					calls += w.ModelCalls
				}
				out["workers"], out["model_calls"] = ws, calls
			}
			// Surface the proposals awaiting review and the decisions the
			// classifier applied, so the assistant can present them without the
			// user knowing to ask. Reported while the run is still going too (the
			// incremental attribution pass records them mid-run), so a watching
			// assistant can raise them in near real time, not only at the end.
			if op.Journal != nil {
				// Both counts cover this run only; list_proposals with pending
				// true shows the journal's whole backlog.
				if s, err := lenscli.PendingProposalsSince(op.Journal, run.StartedAt); err == nil && s.Total > 0 {
					out["pending_proposals"] = s
				}
				// Surface what the classifier applied automatically during this
				// run, so the assistant can tell the user what the AI decided on
				// its own, not only what awaits review.
				if a, err := lenscli.AppliedByAISummary(op.Journal, run.StartedAt); err == nil && a.Total > 0 {
					out["applied_by_ai"] = a
				}
			}

			return jsonResult(out), nil
		})

	t.add(ToolStopEnumeration, "Stop an Amass enumeration", "End a running enumeration and its engine session. "+
		"When the run joined an enumeration other engines share, they carry on with it.",
		obj([]string{"run_id"}, map[string]any{"run_id": map[string]any{"type": "string"}}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
		func(ctx context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				RunID string `json:"run_id"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.Collect == nil {
				return nil, errors.New("no engine is configured")
			}

			run, err := op.Collect.Stop(ctx, a.RunID)
			if err != nil {
				return nil, err
			}

			return jsonResult(map[string]any{"run": run}), nil
		})

	t.approveAction(ToolWatchTarget, "Watch a target with Amass",
		"Re-run the enumeration a plan_enumeration call described on a schedule, so changes to the target are "+
			"collected without asking each time. The user approves the watch once; it runs until stop_watch.",
		obj([]string{"target", "plan_id", "every_hours"}, map[string]any{"target": target, "mode": mode,
			"also": also, "expand": expand, "brute_force": bruteForce, "alterations": alterations,
			"interface": iface, "active_route": activeRoute, "active_udp_route": activeUDPRoute,
			"plan_id": map[string]any{
				"type":        "string",
				"description": "The plan_id plan_enumeration returned",
			},
			"every_hours": map[string]any{"type": "integer", "minimum": int(collect.MinWatchInterval.Hours()),
				"maximum": 24 * 90, "description": "Hours between runs, such as 24 for daily or 168 for weekly"}}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		func(_ context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (string,
			func(via string) (*mcp.CallToolResult, error), error) {
			var a struct {
				Target string
				Mode   string
				Also   []string
				planArgs
				PlanID     string `json:"plan_id"`
				EveryHours int    `json:"every_hours"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return "", nil, err
			}
			if op.Watches == nil {
				return "", nil, errors.New("this server cannot keep watches")
			}

			plan := planFor(a.Target, a.Mode, a.Also, a.options())
			if plan.Status != collect.StatusApprovalRequired {
				return "", nil, errors.New("cannot enumerate this target: " + plan.Reason)
			}
			if a.PlanID != plan.ID {
				return "", nil, errors.New("plan_id does not match this target, mode, also, expand, brute_force, " +
					"alterations, interface and active routes; call plan_enumeration again")
			}

			every := time.Duration(a.EveryHours) * time.Hour
			msg := fmt.Sprintf("Run a %s every %d hours, starting now, until the watch is stopped?\n\n%s",
				plan.Summary(), a.EveryHours, plan.Effects)
			return msg, func(via string) (*mcp.CallToolResult, error) {
				w, err := op.Watches.Add(plan, every, approver(req, via))
				if err != nil {
					return nil, err
				}

				return jsonResult(map[string]any{"watch": w,
					"next": "The first run starts within a minute. list_watches shows what each run found."}), nil
			}, nil
		})

	t.add(ToolListWatches, "Amass watches",
		"List the scheduled enumerations: their scope, schedule, next run, and what the last finished run found.",
		obj(nil, map[string]any{}), readOnly(),
		func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error) {
			if op.Watches == nil {
				return nil, errors.New("this server cannot keep watches")
			}

			return jsonResult(map[string]any{"watches": op.Watches.List()}), nil
		})

	t.add(ToolStopWatch, "Stop an Amass watch", "Remove a scheduled enumeration; a run it started finishes on its own.",
		obj([]string{"watch_id"}, map[string]any{"watch_id": map[string]any{"type": "string"}}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
		func(_ context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				WatchID string `json:"watch_id"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.Watches == nil {
				return nil, errors.New("this server cannot keep watches")
			}

			w, err := op.Watches.Remove(a.WatchID)
			if err != nil {
				return nil, err
			}

			return jsonResult(map[string]any{"removed": w}), nil
		})
}
