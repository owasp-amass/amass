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
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/review"
	oam "github.com/owasp-amass/open-asset-model"
)

// contributeTools are the tools that let an assistant add what it found to
// the Asset Database.
func (t *operatorTools) contributeTools() {
	op := t.op
	ref := map[string]any{"type": "object", "additionalProperties": false,
		"description": "An asset item of this call (item, counted from 0) or a stored asset by an exact field " +
			"(type, field, value), as find_assets and resolve_asset name them",
		"properties": map[string]any{
			"item":  map[string]any{"type": "integer", "minimum": 0},
			"type":  map[string]any{"type": "string"},
			"field": map[string]any{"type": "string"},
			"value": map[string]any{"type": "string"},
		}}
	item := map[string]any{"type": "object", "additionalProperties": false,
		"required": []string{"kind", "evidence"},
		"properties": map[string]any{
			"kind": map[string]any{"type": "string",
				"enum": []string{review.ContributedAsset, review.ContributedRelation, review.ContributedProperty}},
			"asset_type": map[string]any{"type": "string",
				"description": "asset: the OAM asset type, as describe_oam_schema lists them"},
			"fields": map[string]any{"type": "object",
				"description": "asset: the asset's OAM fields; relation: the relation's fields besides its label " +
					"(such as a DNS record header); property: the property's fields (a SimpleProperty's " +
					"property_name and property_value)"},
			"from":  ref,
			"label": map[string]any{"type": "string", "description": "relation: its OAM label"},
			"relation_type": map[string]any{"type": "string",
				"description": "relation: its OAM type (default SimpleRelation)"},
			"to":     ref,
			"target": ref,
			"property_type": map[string]any{"type": "string",
				"enum":        []string{string(oam.SimpleProperty), string(oam.DNSRecordProperty), string(oam.VulnProperty)},
				"description": "property: its OAM type (default SimpleProperty)"},
			"evidence": map[string]any{"type": "string",
				"description": "Where it came from: a URL, a document, a tool and what it returned"},
			"confidence": map[string]any{"type": "integer", "minimum": 0, "maximum": 100,
				"description": "How sure you are, 1..100 (default 50)"},
		}}

	t.approveAction(ToolContribute, "Contribute to the Amass Asset Database",
		fmt.Sprintf("Add what you found by other means (a search, a document, another tool) to the Asset Database "+
			"as OAM assets, relations between assets and properties of assets, up to %d items, each checked "+
			"against the OAM schema and saying where it came from. They are recorded under the source "+
			"amass-ai:<your client name> and count like any other stored data; an enumeration running now is "+
			"given the assets to investigate. The user approves the whole contribution first, and can undo it "+
			"with review_proposal (retract).", review.MaxContributedItems),
		obj([]string{"items"}, map[string]any{
			"items": map[string]any{"type": "array", "items": item, "minItems": 1,
				"maxItems": review.MaxContributedItems},
		}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(false)},
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (string,
			func(via string) (*mcp.CallToolResult, error), error) {
			var a struct {
				Items []review.ContributedItem `json:"items"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return "", nil, err
			}
			if op.Journal == nil {
				return "", nil, errors.New("no review journal is configured, so a contribution could not be undone")
			}
			if err := review.CheckContribution(a.Items); err != nil {
				return "", nil, err
			}

			client := clientName(req)
			var b strings.Builder
			fmt.Fprintf(&b, "Add %d item(s) from %s to the Asset Database, recorded as %s?", len(a.Items), client,
				review.ContributionSource(client))
			for i, it := range a.Items {
				fmt.Fprintf(&b, "\n%d. %s (from %s)", i, it.Describe(), it.Evidence)
			}

			act := func(via string) (*mcp.CallToolResult, error) {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
				defer cancel()
				j := op.Journal
				c, err := review.ApplyContribution(ctx, op.Graph, j, client, approver(req, via), a.Items)
				if err != nil {
					return nil, err
				}

				runs := handToRunning(ctx, op, a.Items)
				if err := j.RecordContributionRuns(c, runs); err == nil {
					c.Runs = runs
				}
				return jsonResult(map[string]any{"contribution": c, "next": "Undo it with review_proposal: " +
					"proposal_id " + c.ID + ", decision retract."}), nil
			}
			return b.String(), act, nil
		})
}

// handToRunning gives the contributed assets to every running enumeration,
// where the engine's expansion policy decides what it investigates, and
// returns the runs that took any.
func handToRunning(ctx context.Context, op *Operator, items []review.ContributedItem) []string {
	if op.Collect == nil {
		return nil
	}

	took := map[string]bool{}
	var runs []string
	for _, it := range items {
		if it.Kind != review.ContributedAsset {
			continue
		}
		asset, err := oamrepo.ContributedAsset(it)
		if err != nil {
			continue
		}

		ids, _ := op.Collect.SubmitToRunning(ctx, asset)
		for _, id := range ids {
			if !took[id] {
				took[id] = true
				runs = append(runs, id)
			}
		}
	}
	return runs
}
