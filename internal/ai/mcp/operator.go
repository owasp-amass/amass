// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	lenscli "github.com/owasp-amass/amass/v5/internal/lens/cli"
)

// Operator holds what the operator tools act on. A server offers them only
// when it has an Operator, and the HTTP server only to clients that present
// the operator token. Every tool that starts collection or writes to the
// Asset Database asks the user to approve it in the client (MCP
// elicitation) when the client can show such a dialog, and otherwise at a
// local approval link (HTTP) or through the client's own tool-call approval
// (stdio), unless RequireConfirmation is set.
type Operator struct {
	Collect *collect.Manager
	// Watches re-run approved plans on a schedule; nil disables watching.
	Watches *collect.Watches
	// Graph writes approved proposals; reads go through the runner.
	Graph oamrepo.Adapter
	// Journal is the review journal automatic attribution writes.
	Journal string
	// DataSources is the datasources file credentials are stored in.
	DataSources string
	// KeyLinks serves one-time pages for entering credentials, and
	// Approvals pages for approving actions in a browser; both are nil when
	// the server cannot serve pages (stdio).
	KeyLinks  *KeyLinks
	Approvals *ApprovalLinks
	// RequireConfirmation refuses actions when the client cannot show an
	// approval dialog.
	RequireConfirmation bool
}

// Operator tool names.
const (
	ToolPlanEnumeration   = "plan_enumeration"
	ToolStartEnumeration  = "start_enumeration"
	ToolEnumerationStatus = "enumeration_status"
	ToolStopEnumeration   = "stop_enumeration"
	ToolListProposals     = "list_proposals"
	ToolReviewProposal    = "review_proposal"
	ToolDataSources       = "data_sources"
	ToolDataSourceKey     = "data_source_key_link"
	ToolWatchTarget       = "watch_target"
	ToolListWatches       = "list_watches"
	ToolStopWatch         = "stop_watch"
)

const operatorInstructions = `

Operator mode: this connection may also act.
- To collect data about a target that is missing or stale, call plan_enumeration (a domain, IP address, CIDR or AS number, and mode passive or active), show the user the plan's scope and effects, then call start_enumeration with the plan_id. The user is asked to approve it, in a dialog or at an approval_url you must give them. Prefer passive; active contacts the target's hosts and needs the user's authorization to test them.
- Follow a run with enumeration_status; when it finishes, its result lists what was found, and investigate answers questions about it. stop_enumeration ends a run.
- list_proposals shows the ownership, merge, identity and person-named proposals awaiting review; review_proposal approves, rejects or retracts one (approving and retracting write to the database and ask the user first).
- watch_target re-runs a planned enumeration on a schedule (at most every 6 hours) after the user approves it once; list_watches shows each watch with what its last run found, and stop_watch removes one.
- data_sources lists which data sources have credentials. data_source_key_link gives the user a one-time local link to enter a key; never ask the user to type a key into the chat.`

func boolPtr(b bool) *bool { return &b }

// addOperatorTools registers the operator tools on server.
func addOperatorTools(server *mcp.Server, op *Operator, runner ai.ToolRunner) {
	target := map[string]any{"type": "string",
		"description": "The exact target: a domain (example.com), an IP address, a CIDR range or an AS number (AS15169)"}
	mode := map[string]any{"type": "string", "enum": []string{string(collect.Passive), string(collect.Active)},
		"description": "passive (default) queries data sources only; active also probes the target's hosts"}
	obj := func(required []string, props map[string]any) map[string]any {
		schema := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(required) > 0 {
			// Clients reject a null required list.
			schema["required"] = required
		}
		return schema
	}

	add := func(name, title, desc string, schema map[string]any, ann *mcp.ToolAnnotations,
		h func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error)) {
		ann.Title = title
		server.AddTool(&mcp.Tool{Name: name, Title: title, Description: desc, InputSchema: schema, Annotations: ann},
			func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var args json.RawMessage
				if req.Params != nil {
					args = req.Params.Arguments
				}
				res, err := h(ctx, req, args)
				if err != nil {
					return errorResult(err), nil
				}
				return res, nil
			})
	}
	readOnly := func() *mcp.ToolAnnotations {
		return &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPtr(false)}
	}

	add(ToolPlanEnumeration, "Plan an Amass enumeration",
		"Show what an enumeration of one exact target would do, without starting it: the scope, the methods, "+
			"their effects, and the plan_id that start_enumeration needs.",
		obj([]string{"target"}, map[string]any{"target": target, "mode": mode}), readOnly(),
		func(_ context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct{ Target, Mode string }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			plan := planFor(a.Target, a.Mode)
			if plan.Status != collect.StatusApprovalRequired {
				return nil, errors.New("cannot enumerate this target: " + plan.Reason)
			}
			return jsonResult(map[string]any{"plan": plan,
				"next": "Show the user the scope and effects, then call start_enumeration with this target, mode " +
					"and plan_id. The user is asked to approve it."}), nil
		})

	add(ToolStartEnumeration, "Start an Amass enumeration",
		"Start the enumeration a plan_enumeration call described. Collects data from the Internet about the "+
			"target and stores it in the Asset Database; the user is asked to approve it first.",
		obj([]string{"target", "plan_id"}, map[string]any{"target": target, "mode": mode,
			"plan_id": map[string]any{"type": "string", "description": "The plan_id plan_enumeration returned"}}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				Target string
				Mode   string
				PlanID string `json:"plan_id"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.Collect == nil {
				return nil, errors.New("this server cannot start enumerations: no engine is configured")
			}
			plan := planFor(a.Target, a.Mode)
			if plan.Status != collect.StatusApprovalRequired {
				return nil, errors.New("cannot enumerate this target: " + plan.Reason)
			}
			if a.PlanID != plan.ID {
				return nil, errors.New("plan_id does not match this target and mode; call plan_enumeration again " +
					"and show the user the new plan")
			}
			msg := fmt.Sprintf("Start a %s?\n\n%s", plan.Summary(), plan.Effects)
			return op.gate(req, msg, func(via string) (*mcp.CallToolResult, error) {
				sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
				defer cancel()
				run, err := op.Collect.Start(sctx, plan, approver(req, via))
				if err != nil {
					return nil, err
				}
				return jsonResult(map[string]any{"run": run,
					"next": "Check progress with enumeration_status; runs end on their own when the work is done."}), nil
			})
		})

	add(ToolEnumerationStatus, "Amass enumeration status",
		"Show the enumerations this server started: state, progress and, for a finished run, what it found. "+
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
			return jsonResult(out), nil
		})

	add(ToolStopEnumeration, "Stop an Amass enumeration", "End a running enumeration and its engine session.",
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

	add(ToolWatchTarget, "Watch a target with Amass",
		"Re-run the enumeration a plan_enumeration call described on a schedule, so changes to the target are "+
			"collected without asking each time. The user approves the watch once; it runs until stop_watch.",
		obj([]string{"target", "plan_id", "every_hours"}, map[string]any{"target": target, "mode": mode,
			"plan_id": map[string]any{"type": "string", "description": "The plan_id plan_enumeration returned"},
			"every_hours": map[string]any{"type": "integer", "minimum": int(collect.MinWatchInterval.Hours()),
				"maximum": 24 * 90, "description": "Hours between runs, such as 24 for daily or 168 for weekly"}}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				Target     string
				Mode       string
				PlanID     string `json:"plan_id"`
				EveryHours int    `json:"every_hours"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.Watches == nil {
				return nil, errors.New("this server cannot keep watches")
			}
			plan := planFor(a.Target, a.Mode)
			if plan.Status != collect.StatusApprovalRequired {
				return nil, errors.New("cannot enumerate this target: " + plan.Reason)
			}
			if a.PlanID != plan.ID {
				return nil, errors.New("plan_id does not match this target and mode; call plan_enumeration again")
			}
			every := time.Duration(a.EveryHours) * time.Hour
			msg := fmt.Sprintf("Run a %s every %d hours, starting now, until the watch is stopped?\n\n%s",
				plan.Summary(), a.EveryHours, plan.Effects)
			return op.gate(req, msg, func(via string) (*mcp.CallToolResult, error) {
				w, err := op.Watches.Add(plan, every, approver(req, via))
				if err != nil {
					return nil, err
				}
				return jsonResult(map[string]any{"watch": w,
					"next": "The first run starts within a minute. list_watches shows what each run found."}), nil
			})
		})

	add(ToolListWatches, "Amass watches",
		"List the scheduled enumerations: their scope, schedule, next run, and what the last finished run found.",
		obj(nil, map[string]any{}), readOnly(),
		func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error) {
			if op.Watches == nil {
				return nil, errors.New("this server cannot keep watches")
			}
			return jsonResult(map[string]any{"watches": op.Watches.List()}), nil
		})

	add(ToolStopWatch, "Stop an Amass watch", "Remove a scheduled enumeration; a run it started finishes on its own.",
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

	add(ToolListProposals, "Amass review proposals",
		"List the proposals awaiting review: ownership relationships, organization merges, identity corrections "+
			"and organizations recorded under a person's name, each with its ID, evidence and status.",
		obj(nil, map[string]any{}), readOnly(),
		func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error) {
			if op.Journal == "" {
				return nil, errors.New("no review journal is configured")
			}
			text, err := lenscli.ProposalsText(op.Journal)
			if err != nil {
				return nil, err
			}
			return textResult(text), nil
		})

	add(ToolReviewProposal, "Review an Amass proposal",
		"Approve, reject or retract one proposal by ID. Approving writes its relationship, merge or correction to "+
			"the Asset Database and retracting removes it; the user is asked first. Rejecting only records the decision.",
		obj([]string{"proposal_id", "decision"}, map[string]any{
			"proposal_id": map[string]any{"type": "string"},
			"decision": map[string]any{"type": "string",
				"enum": []string{lenscli.DecisionApprove, lenscli.DecisionReject, lenscli.DecisionRetract}},
		}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				ProposalID string `json:"proposal_id"`
				Decision   string
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.Journal == "" {
				return nil, errors.New("no review journal is configured")
			}
			decide := func(via string) (*mcp.CallToolResult, error) {
				dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
				defer cancel()
				text, err := lenscli.Decide(dctx, op.Graph, op.Journal, a.Decision, a.ProposalID, approver(req, via))
				if err != nil {
					return nil, err
				}
				return textResult(text), nil
			}
			if a.Decision == lenscli.DecisionReject || a.Decision == "" {
				return decide("no write")
			}
			msg := fmt.Sprintf("%s proposal %s? This changes the Asset Database.",
				strings.ToUpper(a.Decision[:1])+a.Decision[1:], a.ProposalID)
			return op.gate(req, msg, decide)
		})

	add(ToolDataSources, "Amass data sources",
		"List the data sources the enumeration engine can use and whether each has credentials configured. "+
			"Never shows the credentials.",
		obj(nil, map[string]any{}), readOnly(),
		func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error) {
			if op.DataSources == "" {
				return nil, errors.New("no datasources file is configured")
			}
			st, err := collect.DataSourceStatus(op.DataSources)
			if err != nil {
				return nil, err
			}
			var with, without []string
			for _, s := range st {
				if s.Configured {
					with = append(with, s.Name)
				} else {
					without = append(without, s.Name)
				}
			}
			return jsonResult(map[string]any{"configured": with, "without_credentials": without,
				"note": "Sources without credentials are skipped. Use data_source_key_link to let the user add a key."}), nil
		})

	add(ToolDataSourceKey, "Link to add a data source key",
		"Create a one-time local link where the user enters credentials for one data source. The credentials go "+
			"straight from the user's browser to the datasources file, never through this conversation.",
		obj([]string{"source"}, map[string]any{"source": map[string]any{"type": "string",
			"description": "The data source name as data_sources lists it"}}),
		&mcp.ToolAnnotations{OpenWorldHint: boolPtr(false)},
		func(_ context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct{ Source string }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.KeyLinks == nil || op.DataSources == "" {
				return nil, errors.New("this connection cannot serve key links; add the key to the datasources " +
					"file (config/datasources.yaml in the Compose stack)")
			}
			link, expires, err := op.KeyLinks.New(a.Source)
			if err != nil {
				return nil, err
			}
			return jsonResult(map[string]any{"url": link, "expires": expires.Format(time.RFC3339),
				"next": "Give the user this link to open in a browser on the computer running Amass. It works once."}), nil
		})
}

// confirmKey names the approval input request.
const confirmKey = "amass_approval"

// gate asks the user to approve an action and carries it out once they do.
// In order of preference: the client's approval dialog (MCP elicitation), a
// local approval link the user opens in a browser, or, when the server has
// neither and does not require confirmation, the client's own tool-call
// approval. act receives how the action was approved.
func (op *Operator) gate(req *mcp.CallToolRequest, message string,
	act func(via string) (*mcp.CallToolResult, error)) (*mcp.CallToolResult, error) {
	if req.Params != nil {
		if resp, ok := req.Params.InputResponses[confirmKey]; ok {
			r, _ := resp.(*mcp.ElicitResult)
			if r != nil && r.Action == "accept" && r.Content["approve"] == true {
				return act("approval dialog")
			}
			return nil, errors.New("the user did not approve this action; nothing was done")
		}
	}

	if elicitable(req) {
		return &mcp.CallToolResult{InputRequests: mcp.InputRequestMap{confirmKey: &mcp.ElicitParams{
			Mode:    "form",
			Message: message,
			RequestedSchema: map[string]any{"type": "object", "required": []string{"approve"},
				"properties": map[string]any{"approve": map[string]any{"type": "boolean", "title": "Approve",
					"description": "Check to approve this action", "default": false}}},
		}}}, nil
	}
	if op.Approvals != nil {
		link, expires, err := op.Approvals.New(message, func() (string, error) {
			res, err := act("approval link")
			if err != nil {
				return "", err
			}
			return resultText(res), nil
		})
		if err != nil {
			return nil, err
		}
		return jsonResult(map[string]any{"status": "awaiting_approval", "approval_url": link,
			"expires": expires.Format(time.RFC3339),
			"next": "Nothing has happened yet. Ask the user to open approval_url in a browser on the computer " +
				"running Amass and press Approve; then check the result (enumeration_status for an enumeration)."}), nil
	}
	if op.RequireConfirmation {
		return nil, errors.New("this client cannot show an approval dialog (MCP elicitation), and the " +
			"server requires one for this action; use a client that supports it")
	}
	return act("client tool approval")
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	if res != nil {
		for _, c := range res.Content {
			if t, ok := c.(*mcp.TextContent); ok {
				b.WriteString(t.Text)
			}
		}
	}
	return b.String()
}

func elicitable(req *mcp.CallToolRequest) bool {
	if req == nil || req.Session == nil {
		return false
	}
	p := req.Session.InitializeParams()
	return p != nil && p.Capabilities != nil && p.Capabilities.Elicitation != nil
}

// approver records who approved an action, as specifically as the session
// allows.
func approver(req *mcp.CallToolRequest, via string) string {
	client := "mcp client"
	if req != nil && req.Session != nil {
		if p := req.Session.InitializeParams(); p != nil && p.ClientInfo != nil && p.ClientInfo.Name != "" {
			client = p.ClientInfo.Name
		}
	}
	return fmt.Sprintf("mcp:%s (%s)", client, via)
}

var asNumber = regexp.MustCompile(`^(?i:as)?(\d{1,10})$`)

// planFor reads a target as a user writes it.
func planFor(target, mode string) collect.Plan {
	target = strings.TrimSpace(target)
	m := collect.Mode(strings.ToLower(strings.TrimSpace(mode)))
	if m == "" {
		m = collect.Passive
	}

	sel := graph.AssetSelector{Type: "FQDN", Field: "name", Value: target}
	switch {
	case strings.Contains(target, "/"):
		sel = graph.AssetSelector{Type: "Netblock", Field: "cidr", Value: target}
	case asNumber.MatchString(target):
		sel = graph.AssetSelector{Type: "AutonomousSystem", Field: "number", Value: asNumber.FindStringSubmatch(target)[1]}
	default:
		if _, err := netip.ParseAddr(target); err == nil {
			sel = graph.AssetSelector{Type: "IPAddress", Field: "address", Value: target}
		}
	}
	return collect.NewPlan(sel, m)
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

func jsonResult(v any) *mcp.CallToolResult {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorResult(err)
	}
	return textResult(string(data))
}

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func errorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}
}
