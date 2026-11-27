// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	lenscli "github.com/owasp-amass/amass/v5/internal/lens/cli"
	"github.com/owasp-amass/amass/v5/internal/review"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oam "github.com/owasp-amass/open-asset-model"
)

// contribute shows the user every item before writing; an approved
// contribution is stored under the client's source, listed for review, and
// undone by a retraction.
func TestContributeAsksTheUserAndCanBeRetracted(t *testing.T) {
	fx := newOperatorFixture(t)
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "contribute.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	fx.op.Graph = oamrepo.Adapter{Repo: repo}

	var asked []string
	answer := "decline"
	cs := connect(t, fx.url, operatorToken, func(r *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		asked = append(asked, r.Params.Message)
		if answer == "accept" {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
		}
		return &mcp.ElicitResult{Action: answer}, nil
	})

	args := map[string]any{"items": []any{map[string]any{"kind": "asset", "asset_type": "FQDN",
		"fields": map[string]any{"name": "contributed.example.com"}, "evidence": "the user's notes"}}}
	if text, isErr := call(t, cs, ToolContribute, map[string]any{"items": []any{map[string]any{
		"kind": "asset", "asset_type": "FQDN", "fields": map[string]any{"name": "x.example.com"}}}}); !isErr ||
		!strings.Contains(text, "evidence") || len(asked) != 0 {
		t.Fatalf("an item without evidence reached the user: %s", text)
	}

	text, isErr := call(t, cs, ToolContribute, args)
	if !isErr || !strings.Contains(text, "did not approve") {
		t.Fatalf("a declined contribution: %s", text)
	}
	if len(asked) != 1 || !strings.Contains(asked[0], "contributed.example.com") ||
		!strings.Contains(asked[0], "amass-ai:test-client") || !strings.Contains(asked[0], "the user's notes") {
		t.Fatalf("approval prompt = %q", asked)
	}
	if ents, _ := repo.FindEntitiesByContent(context.Background(), oam.FQDN, time.Time{}, 1,
		map[string]any{"name": "contributed.example.com"}); len(ents) != 0 {
		t.Fatal("a declined contribution was stored")
	}

	answer = "accept"
	text, isErr = call(t, cs, ToolContribute, args)
	var out struct{ Contribution review.Contribution }
	if isErr || json.Unmarshal([]byte(text), &out) != nil || !review.IsContribution(out.Contribution.ID) {
		t.Fatalf("an approved contribution: %s", text)
	}
	if ents, err := repo.FindEntitiesByContent(context.Background(), oam.FQDN, time.Time{}, 1,
		map[string]any{"name": "contributed.example.com"}); err != nil || len(ents) != 1 {
		t.Fatalf("stored = %v, %v", ents, err)
	}

	listed, _ := call(t, cs, ToolListProposals, map[string]any{})
	if !strings.Contains(listed, out.Contribution.ID) {
		t.Errorf("list_proposals lacks the contribution: %s", listed)
	}
	if text, isErr := call(t, cs, ToolReviewProposal, map[string]any{"proposal_id": out.Contribution.ID,
		"decision": lenscli.DecisionReject}); !isErr || !strings.Contains(text, "retract") {
		t.Errorf("rejecting a contribution: %s", text)
	}
	if text, isErr := call(t, cs, ToolReviewProposal, map[string]any{"proposal_id": out.Contribution.ID,
		"decision": lenscli.DecisionRetract}); isErr {
		t.Fatalf("retracting the contribution: %s", text)
	}
	if ents, _ := repo.FindEntitiesByContent(context.Background(), oam.FQDN, time.Time{}, 1,
		map[string]any{"name": "contributed.example.com"}); len(ents) != 0 {
		t.Fatal("the retracted contribution is still stored")
	}
}
