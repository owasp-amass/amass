// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/asset-db/repository"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// The changes lens reads the first-stored and last-seen times the
// repository keeps for assets and relations.
func TestChangesOnSQLite(t *testing.T) {
	checkChanges(t, openSQLite(t, "changes.db"))
}

func checkChanges(t *testing.T, repo repository.Repository) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}
	before := time.Now().Add(-time.Hour)

	apex := f.asset(&oamdns.FQDN{Name: "example.edu"})
	www := f.asset(&oamdns.FQDN{Name: "www.example.edu"})
	f.edge(apex, www, "node", "DNS")

	adapter := Adapter{Repo: repo}
	root, err := adapter.GetAsset(ctx, apex.ID)
	if err != nil {
		t.Fatal(err)
	}
	if root.CreatedAt.IsZero() || root.LastSeen.IsZero() {
		t.Fatalf("the adapter returned no stored times: %+v", root)
	}

	r, err := lens.FindChanges(ctx, adapter, Catalog{}, root, before, lens.LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	newNames := 0
	for _, g := range r.NewAssets {
		if g.Key == "FQDN" {
			newNames = g.Count
		}
	}
	if newNames != 2 || len(r.NewRelations) == 0 || len(r.QuietAssets) != 0 {
		t.Errorf("changes = %+v\n%s", r, lens.FormatChangesReport(r))
	}
}
