// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/graph"
	lenscli "github.com/owasp-amass/amass/v5/internal/lens/cli"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// reviewTools are the tools that list, watch and decide review proposals.
func (t *operatorTools) reviewTools() {
	op, runner := t.op, t.runner

	t.add(ToolListProposals, "Amass review proposals",
		"List the proposals awaiting review: ownership relationships, organization merges, identity corrections, "+
			"organizations recorded under a person's name, people recorded under an organization's name and "+
			"names to decide as a person or an organization, each with its ID, evidence and status, and the "+
			"contributions assistants made with the contribute tool. Set "+
			"\"pending\" to list only the proposals still awaiting a decision, so newly-proposed items can be "+
			"surfaced for the user to decide on immediately.",
		obj(nil, map[string]any{
			"pending": map[string]any{"type": "boolean",
				"description": "List only proposals that are still awaiting a decision."},
			"applied": map[string]any{"type": "boolean",
				"description": "List instead the changes the AI classifier applied automatically."},
			"lead": map[string]any{"type": "string",
				"description": "Show one document lead (doclead:<run>:<entity>, as applied lists them) instead: " +
					"its document, how it settled and, when confirmed, each asset it led to."},
		}), readOnly(),
		func(ctx context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			if op.Journal == nil {
				return nil, errors.New("no review journal is configured")
			}

			var a struct {
				Pending bool   `json:"pending"`
				Applied bool   `json:"applied"`
				Lead    string `json:"lead"`
			}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &a); err != nil {
					return nil, err
				}
			}

			if a.Lead != "" {
				if runner.Graph == nil {
					return nil, errors.New("no asset database is open")
				}
				text, err := lenscli.LeadFootprintText(op.Journal, a.Lead, func(id string) (graph.Asset, bool) {
					asset, err := runner.Graph.GetAsset(ctx, id)
					return asset, err == nil
				})
				if err != nil {
					return nil, err
				}
				return textResult(text), nil
			}

			text, err := lenscli.ProposalsText(op.Journal)
			switch {
			case a.Applied:
				text, err = lenscli.AppliedProposalsTextLive(op.Journal, entityExists(ctx, runner.Graph))
			case a.Pending:
				text, err = lenscli.PendingProposalsTextLive(op.Journal, entityExists(ctx, runner.Graph))
			}
			if err != nil {
				return nil, err
			}

			return textResult(text), nil
		})

	t.add(ToolWatchDecisions, "Watch Amass decisions",
		"Wait for new review items while an enumeration runs: proposals that now await the user's decision and "+
			"changes the AI classifier applied on its own (ownership edges, organization merges, identity "+
			"corrections, scope expansions, document leads). Call it first without a cursor to start from now; then pass the "+
			"cursor it returns. Each call returns as soon as new items are written, or after wait_seconds with "+
			"none, with the cursor for the next call. Reads the review journal only; it changes nothing.",
		obj(nil, map[string]any{
			"cursor": map[string]any{"type": "string",
				"description": "The cursor a previous call returned; omit to start from now."},
			"wait_seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": maxDecisionWait,
				"description": fmt.Sprintf("How long to wait for new items (default %d, at most %d).",
					defaultDecisionWait, maxDecisionWait)},
		}), readOnly(),
		func(ctx context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			if op.Journal == nil {
				return nil, errors.New("no review journal is configured")
			}
			if !op.AnnounceDecisions {
				return textResult("Decision announcements are turned off (attribution is off, or " +
					"AMASS_AI_ANNOUNCE_DECISIONS is false). list_proposals still lists proposals and applied " +
					"changes on request."), nil
			}

			var a struct {
				Cursor string `json:"cursor"`
				Wait   *int   `json:"wait_seconds"`
			}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &a); err != nil {
					return nil, err
				}
			}

			wait := defaultDecisionWait
			if a.Wait != nil {
				wait = min(max(*a.Wait, 0), maxDecisionWait)
			}

			return watchDecisions(ctx, op.Journal, a.Cursor, time.Duration(wait)*time.Second,
				entityExists(ctx, runner.Graph))
		})

	t.add(ToolReviewProposal, "Review an Amass proposal",
		"Approve, reject or retract one proposal by ID. Approving writes its relationship, merge or correction to "+
			"the Asset Database and retracting removes it; the user is asked first. Rejecting only records the decision. "+
			"Approving a name proposal (nk-...) needs as: whether the name is a person or an organization. "+
			"Approving or rejecting one decides every pending proposal of the same name in the same field "+
			"(the listing shows them under one ID), unless only is true. A contribution (ctb-...) was applied "+
			"when the user approved it, so it can only be retracted, which removes what only it recorded.",
		obj([]string{"proposal_id", "decision"}, map[string]any{
			"proposal_id": map[string]any{"type": "string"},
			"decision": map[string]any{"type": "string",
				"enum": []string{lenscli.DecisionApprove, lenscli.DecisionReject, lenscli.DecisionRetract}},
			"as": map[string]any{"type": "string",
				"enum": []string{review.NameKindPerson, review.NameKindOrganization}},
			"only": map[string]any{"type": "boolean",
				"description": "Decide just this name proposal, not the others of the same name"},
		}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				ProposalID string `json:"proposal_id"`
				Decision   string
				As         string
				Only       bool
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.Journal == nil {
				return nil, errors.New("no review journal is configured")
			}

			decide := func(via string) (*mcp.CallToolResult, error) {
				dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
				defer cancel()
				text, err := lenscli.Decide(dctx, op.Graph, op.Journal, a.Decision, a.ProposalID, a.As,
					approver(req, via), a.Only)
				if err != nil {
					return nil, err
				}

				return textResult(text), nil
			}
			if a.Decision == lenscli.DecisionReject || a.Decision == "" {
				return decide("no write")
			}

			target := a.ProposalID
			if a.As != "" {
				target += " as " + a.As
			}
			if review.IsNameKindProposal(a.ProposalID) && a.Decision == lenscli.DecisionApprove && !a.Only {
				target += ", and every pending proposal of the same name in the same field"
			}
			msg := fmt.Sprintf("%s proposal %s? This changes the Asset Database.",
				strings.ToUpper(a.Decision[:1])+a.Decision[1:], target)
			return op.gate(req, msg, decide)
		})
}

// documentTools are the tools that have the document model read documents.
func (t *operatorTools) documentTools() {
	op := t.op

	t.approveAction(ToolReadDocuments, "Read documents with the document model",
		"Have the document model named in the options.ai.documents configuration read the documents a domain or "+
			"organization publishes, all of each document's text (fetched again, from the archive copy the engine "+
			"read when it read one; the database keeps no copy), and store what they state in Open Asset Model "+
			"terms (assets, relations, field values) as amass-ai observations, undoable. Each finding is checked "+
			"against the text: its quote is in the document, its names are written there, its types and relations "+
			"are ones OAM allows, and a relation is not negated. Each version of a document is read once. Reads at "+
			"most max_documents (default 2) per call; call again while remaining is above zero. The document "+
			"text goes to that model only; the result holds counts unless the configuration shares documents "+
			"with assistants.",
		obj(nil, map[string]any{
			"domain": map[string]any{"type": "string", "description": "The domain whose documents are read"},
			"organization": map[string]any{"type": "string",
				"description": "Instead of a domain, the exact name of a stored organization"},
			"max_documents": map[string]any{"type": "integer", "minimum": 1, "maximum": maxDocumentsPerCall,
				"description": "Most documents read in this call (default 2)"},
			"dry_run": map[string]any{"type": "boolean",
				"description": "Read and validate without storing anything"},
			"reread": map[string]any{"type": "boolean",
				"description": "Read documents again even when their version was read, undoing the earlier findings"},
		}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (string,
			func(via string) (*mcp.CallToolResult, error), error) {
			var a struct {
				Domain       string
				Organization string
				MaxDocuments int  `json:"max_documents"`
				DryRun       bool `json:"dry_run"`
				Reread       bool
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return "", nil, err
			}

			model, modelID, timeout, err := ai.DocumentModel(op.Documents)
			if err != nil {
				return "", nil, err
			}
			if op.Graph.Repo == nil {
				return "", nil, errors.New("no Asset Database is open")
			}
			// the document model's findings are read as stored; this graph is
			// never handed to the client
			dg := op.Graph
			dg.WithholdDocumentText = false
			root, err := ai.DocumentRoot(ctx, dg, a.Domain, a.Organization)
			if err != nil {
				return "", nil, err
			}
			limit := a.MaxDocuments
			if limit <= 0 {
				limit = defaultDocumentsPerCall
			}
			limit = min(limit, maxDocumentsPerCall)

			action := "store the statements it finds on them as amass-ai observations"
			if a.DryRun {
				action = "check the statements it finds without storing them"
			}
			msg := fmt.Sprintf("Fetch up to %d documents published by %s and send their full text to the document "+
				"model %s, and %s?", limit, graph.AssetLabel(root), modelID, action)
			return msg, func(via string) (*mcp.CallToolResult, error) {
				run, err := ai.ReadDocuments(ctx, dg, op.Graph.Repo, op.Journal, root,
					ai.DocumentRunOptions{Model: model, ModelID: modelID, ModelTimeout: timeout,
						Pages: ai.DocumentPages(op.Documents, model), ChunkChars: op.Documents.ChunkChars,
						Max: limit, Reread: a.Reread, DryRun: a.DryRun, Actor: approver(req, via)})
				if err != nil {
					return nil, err
				}

				result := map[string]any{"run": run}
				if op.ShareDocuments {
					stored := map[string][]review.StoredStatement{}
					for _, d := range run.Documents {
						if len(d.Stored) > 0 {
							stored[d.URL] = d.Stored
						}
					}
					result["statements"] = stored
				}
				if run.Remaining > 0 {
					result["next"] = fmt.Sprintf("%d documents remain; call read_documents again to read them.",
						run.Remaining)
				}
				return jsonResult(result), nil
			}, nil
		})
}
