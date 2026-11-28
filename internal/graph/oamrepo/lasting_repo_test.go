// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// A lasting cache refreshed after writes, a deletion and a merge reads what
// the database holds, as a graph without it does.
func TestLastingCacheReadsWhatTheDatabaseHolds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	repo := openSQLite(t, "lasting.db")
	f := mergeFixture{t: t, ctx: ctx, repo: repo}
	adapter := Adapter{Repo: repo}
	lc := graph.NewLastingCache(Adapter{Repo: repo, Stats: &ReadStats{}})

	ident := func(value string) *dbt.Entity {
		return f.asset(&oamgen.Identifier{UniqueID: oamgen.OrganizationName + ":" + value, ID: value,
			Type: oamgen.OrganizationName})
	}

	org := f.asset(&oamorg.Organization{ID: "owasp", Name: "OWASP Foundation"})
	name := ident("OWASP Foundation")
	f.edge(org, name, "id", "test")
	apex := f.asset(&oamdns.FQDN{Name: "owasp.org"})
	www := f.asset(&oamdns.FQDN{Name: "www.owasp.org"})
	dns := f.edge(apex, www, "node", "test")
	ids := []string{org.ID, name.ID, apex.ID, www.ID}

	same := func(step string) {
		t.Helper()
		g, err := lc.Refresh(ctx)
		if err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		for _, id := range ids {
			wantAsset, wantErr := adapter.GetAsset(ctx, id)
			gotAsset, gotErr := g.GetAsset(ctx, id)
			if (wantErr == nil) != (gotErr == nil) || !reflect.DeepEqual(wantAsset, gotAsset) {
				t.Errorf("%s: asset %s is %+v (%v), want %+v (%v)", step, id, gotAsset, gotErr, wantAsset, wantErr)
			}
			if wantErr != nil {
				continue
			}
			for _, dir := range []string{"in", "out"} {
				want, err := adapter.Edges(ctx, id, dir, "", time.Time{})
				if err != nil {
					t.Fatal(err)
				}
				got, err := g.Edges(ctx, id, dir, "", time.Time{})
				if err != nil {
					t.Fatal(err)
				}
				byID := func(a, b graph.Relation) int { return strings.Compare(a.ID, b.ID) }
				slices.SortFunc(want, byID)
				slices.SortFunc(got, byID)
				if !reflect.DeepEqual(want, got) {
					t.Errorf("%s: %s edges of %s are %+v, want %+v", step, dir, id, got, want)
				}
			}
			want, err := adapter.Evidence(ctx, id, 50)
			if err != nil {
				t.Fatal(err)
			}
			got, err := g.Evidence(ctx, id, 50)
			if err != nil {
				t.Fatal(err)
			}
			if len(want) != len(got) {
				t.Errorf("%s: %s has %d pieces of evidence, want %d", step, id, len(got), len(want))
			}
		}
	}

	same("first read")
	same("nothing written")

	// writes: a new relation, a property and a new asset
	mail := f.asset(&oamdns.FQDN{Name: "mail.owasp.org"})
	ids = append(ids, mail.ID)
	f.edge(apex, mail, "node", "test")
	if _, err := repo.CreateEntityProperty(ctx, www, &oamgen.SimpleProperty{PropertyName: "note",
		PropertyValue: "seen again"}); err != nil {
		t.Fatal(err)
	}
	same("writes")

	// a deletion
	if err := repo.DeleteEdge(ctx, dns.ID); err != nil {
		t.Fatal(err)
	}
	same("a deletion")

	// a merge moves the duplicate's relations and deletes it
	dup := f.asset(&oamorg.Organization{ID: "owasp-dup", Name: "OWASP Foundation Inc"})
	dupName := ident("OWASP Foundation Inc")
	f.edge(dup, dupName, "id", "test")
	ids = append(ids, dup.ID, dupName.ID)
	same("a duplicate")
	if _, err := adapter.MergeOrganizations(ctx, org.ID, dup.ID, 90); err != nil {
		t.Fatal(err)
	}
	same("a merge")
}
