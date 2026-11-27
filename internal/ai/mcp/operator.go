// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	lenscli "github.com/owasp-amass/amass/v5/internal/lens/cli"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/secrets"
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
	// Journal is the review journal automatic attribution writes, kept in
	// the database when it keeps one; nil when none is configured.
	Journal *review.Journal
	// AnnounceDecisions lets watch_decisions report new proposals and the
	// classifier's automatic changes as they are written (default on while
	// attribution runs; AMASS_AI_ANNOUNCE_DECISIONS=false turns it off). It
	// controls surfacing only, never whether the classifier acts.
	AnnounceDecisions bool
	// DataSources is the datasources file credentials are stored in.
	DataSources string
	// Secrets is the database's encrypted store of credentials, shared by
	// every engine on the database; nil without the secrets key.
	Secrets *secrets.Store
	// KeyLinks serves one-time pages for entering credentials, and
	// Approvals pages for approving actions in a browser; both are nil when
	// the server cannot serve pages (stdio).
	KeyLinks  *KeyLinks
	Approvals *ApprovalLinks
	// RequireConfirmation refuses actions when the client cannot show an
	// approval dialog.
	RequireConfirmation bool
	// Documents is the document model the user named (options.ai.documents); nil
	// means no model reads documents. ShareDocuments lets read_documents
	// return the statements it stored, quotes included.
	Documents      *config.DocumentModelSettings
	ShareDocuments bool
}

// Operator tool names.
const (
	ToolPlanEnumeration   = "plan_enumeration"
	ToolStartEnumeration  = "start_enumeration"
	ToolEnumerationStatus = "enumeration_status"
	ToolStopEnumeration   = "stop_enumeration"
	ToolListProposals     = "list_proposals"
	ToolWatchDecisions    = "watch_decisions"
	ToolReviewProposal    = "review_proposal"
	ToolDataSources       = "data_sources"
	ToolDataSourceKey     = "data_source_key_link"
	ToolWatchTarget       = "watch_target"
	ToolListWatches       = "list_watches"
	ToolStopWatch         = "stop_watch"
	ToolReadDocuments     = "read_documents"
	ToolContribute        = "contribute"
)

// defaultDocumentsPerCall and maxDocumentsPerCall bound the documents one
// read_documents call reads, so a call ends within a client's tool timeout.
const (
	defaultDocumentsPerCall = 2
	maxDocumentsPerCall     = 10
)

const operatorInstructions = `

Operator mode: this connection can also collect data and change the database, each time with the user's approval. When the user asks for an enumeration, or a question needs data the database lacks, use the tools below rather than declining: the server asks the user to approve every enumeration itself, so its approval step is the user's consent, and nothing runs without it. Only the user decides whether to approve; never approve on their behalf.
- To collect data about a target that is missing or stale, call plan_enumeration (a domain, IP address, CIDR or AS number, and mode passive or active; also lists more targets for the same run, such as the organization's netblocks and AS, and expand true allows scope expansion, only when the user asks for it), show the user the plan's scope and effects, then call start_enumeration with the same arguments and the plan_id. The user is asked to approve it, in a dialog or at an approval_url you must give them. Prefer passive; active contacts the target's hosts and needs the user's authorization to test them.
- To start from a phone number or a street address instead of a target, give plan_enumeration a phone or address: it resolves the organizations tied to the seed and plans a passive enumeration of their registered domains (never the phone or address itself). Show the user the resolved organizations and domains the plan lists before start_enumeration. A shared or registered-agent address is reported and not enumerated; a seed not yet in the database plans a passive resolution pass, after which you plan again to review and enumerate the domains found.
- Follow a run with enumeration_status; when it finishes, its result lists what was found, and investigate answers questions about it. stop_enumeration ends a run. A finished run also reports pending_proposals (counts by kind) when the run left proposals awaiting review.
- Engines that share the database share enumerations: when another engine is already enumerating the same scope, start_enumeration joins that enumeration's job instead of starting another. The run then reports joined true with the job's ID, works under the job's configuration, and shares its queue, scope and decisions; tell the user. Its progress is the whole job's, and it finishes when the job's work is done; enumeration_status with its run_id lists the job's workers (engine sessions) with the items each holds and did and the main model's requests each made, and model_calls, the job's total. stop_enumeration ends this server's part; the other engines' workers carry on.
- When a run reports pending_proposals, present them for the user to decide on: call list_proposals with pending true, group them by kind, and for each explain the evidence behind it with get_evidence and walk_relations (for example, that two organization records share an LEI and a registrant phone, so they are likely the same company, or how an identity contradicts the evidence). Then review_proposal approves, rejects or retracts one; approving and retracting write to the database and ask the user first. Never approve on the user's behalf — the decision is theirs. list_proposals also shows every ownership, merge, identity, person-named, org-named and name proposal when pending is false.
- A finished run also reports applied_by_ai (counts by kind) for the changes the classifier applied automatically during the run (ownership edges, organization merges, identity corrections, scope expansions, and document leads: organizations the document model found named in the run's documents and gave the run to check). Tell the user what the AI decided on its own and explain the evidence with get_evidence and walk_relations; list_proposals with applied true lists them. These are already applied, so the only action is review_proposal retract to undo one — ask the user first, and never retract on their behalf.
- To keep the user aware in near real time, offer to watch a run the user starts or points you at. Call watch_decisions once without a cursor to start from now, then call it again with the cursor it returned, in a loop: each call waits until a new proposal or an AI-applied change is written to the review journal (or up to its wait time) and returns those items with the next cursor. Surface each item at once — explain its evidence with get_evidence and walk_relations, ask the user before any decision, and never approve or retract on their behalf — and check enumeration_status between calls to stop when the run finishes or the user says so. This is user-initiated, so watch when asked.
- watch_target re-runs a planned enumeration on a schedule (at most every 6 hours) after the user approves it once; a due run joins the scope's enumeration if another engine is running it. list_watches shows each watch with what its last run found, and stop_watch removes one.
- When the configuration names a document model (options.ai.documents), read_documents has it read a domain's or organization's documents, all of each document's text (fetched again; the database keeps no copy), and stores what they state in OAM terms (assets, relations, field values) after checking each finding against the text, with the user's approval; each version of a document is read once. Call it again while it reports remaining documents. While an enumeration this server started runs, the document model also reads its documents on its own and gives the run the assets they name that the database lacks (hosts, networks, addresses, phones, emails, URLs and organizations; an organization the document ties to none of the others goes last, within a fifth of the budget) as leads; enumeration_status shows this in the run's activity (documents_read, chunks_read, statements, leads, leads_waiting, and document_failures with document_failures_<why>: fetch, too_large, unsupported, extract, model_timeout, model). The number of leads adapts to how many the engine confirms and to the run's size. When the run ends, leads the engine confirmed stay (with what they led to recorded), and the rest expire. The document text goes only to that model; you see counts unless documents are shared with assistants.
- When the user wants something you found or were told added to the database (an asset, a relation between two assets, or a property on one), call contribute with up to 50 items, each with the evidence for it; describe_oam_schema gives the types and fields. A relation or property names its assets by an earlier item's index or by type, field and value, and each must match exactly one stored asset. The user approves the exact list; the items are recorded with the source amass-ai:<client>, and new assets go to the running enumerations too. A contribution is listed with list_proposals, and review_proposal retract undoes it, removing only what nothing else recorded.
- data_sources lists which data sources have credentials and where each comes from (credentials_from: the environment or the database's encrypted store; the rest from the datasources file). data_source_key_link gives the user a one-time local link to enter a key: when the server has the secrets key, the key is stored encrypted in the database, where every engine on it uses it; otherwise it goes to the datasources file. The operator can also run amass secrets set. Never ask the user to type a key into the chat.
- To change how enumerations run, draft a complete configuration (describe_config gives the schema, current settings and a template), check it with validate_config, then call apply_config with the same content; the user approves the exact change and sees a masked diff. Never put data source credentials in a configuration; the operator adds keys through data_source_key_link.`

func boolPtr(b bool) *bool { return &b }

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
	return fmt.Sprintf("mcp:%s (%s)", clientName(req), via)
}

// clientName is the name the MCP client gave when it connected.
func clientName(req *mcp.CallToolRequest) string {
	if req != nil && req.Session != nil {
		if p := req.Session.InitializeParams(); p != nil && p.ClientInfo != nil && p.ClientInfo.Name != "" {
			return p.ClientInfo.Name
		}
	}
	return "mcp client"
}

var asNumber = regexp.MustCompile(`^(?i:as)?(\d{1,10})$`)

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

// entityExists returns a check that an entity is still in the Asset Database,
// cached for one tool call. Only a lookup that finds no row says an entity is
// gone; any other error (the database unreachable) is not read as gone, so a
// listing never hides proposals because of an outage.
func entityExists(ctx context.Context, g graph.Graph) lenscli.EntityExists {
	if g == nil {
		return nil
	}

	cache := map[string]bool{}
	return func(id string) bool {
		if v, ok := cache[id]; ok {
			return v
		}

		_, err := g.GetAsset(ctx, id)
		ok := err == nil || !missingEntity(err)
		cache[id] = ok
		return ok
	}
}

// missingEntity reports whether a lookup error means the entity is not
// stored, as the SQL backends report it.
func missingEntity(err error) bool {
	return errors.Is(err, sql.ErrNoRows) || strings.Contains(strings.ToLower(err.Error()), "no rows")
}
