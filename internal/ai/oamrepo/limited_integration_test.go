// SPDX-License-Identifier: Apache-2.0
package oamrepo

import (
    "context"
    "path/filepath"
    "testing"
    "time"

    assetdb "github.com/owasp-amass/asset-db"
    "github.com/owasp-amass/asset-db/repository/sqlite3"
    dbt "github.com/owasp-amass/asset-db/types"
    oamdns "github.com/owasp-amass/open-asset-model/dns"
    oamgen "github.com/owasp-amass/open-asset-model/general"
    oamorg "github.com/owasp-amass/open-asset-model/org"
)

// This runs in paired-branch CI against the asset-db feature branch.
// The currently released asset-db may not have the bounded API yet.
func TestAdapterBoundedTraversalOnSQLite(t *testing.T) {
    repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "bounded-adapter.db"))
    if err != nil { t.Fatal(err) }
    defer func() { _ = repo.Close() }()
    if _, ok := repo.(interface {
        ReadEdgesLimited(context.Context, *dbt.Entity, string, time.Time, int, ...string) ([]*dbt.Edge, bool, error)
    }); !ok {
        t.Skip("bounded reader not yet present in released asset-db; paired feature-branch test must execute")
    }
    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
    defer cancel()
    root, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name:"root.example"})
    if err != nil { t.Fatal(err) }
    for _, name := range []string{"a.root.example", "b.root.example"} {
        dest,err:=repo.CreateAsset(ctx, &oamdns.FQDN{Name:name})
        if err!=nil {t.Fatal(err)}
        if _,err=repo.CreateEdge(ctx,&dbt.Edge{FromEntity:root,ToEntity:dest,Relation:&oamgen.SimpleRelation{Name:"node"}});err!=nil {t.Fatal(err)}
    }
    adapter:=Adapter{Repo:repo}
    edges,more,err:=adapter.EdgesLimited(ctx,root.ID,"out","node",time.Time{},1)
    if err!=nil || len(edges)!=1 || !more {t.Fatalf("bounded page: len=%d more=%v err=%v",len(edges),more,err)}
    edges,more,err=adapter.EdgesLimited(ctx,root.ID,"out","node",time.Time{},2)
    if err!=nil || len(edges)!=2 || more {t.Fatalf("complete page: len=%d more=%v err=%v",len(edges),more,err)}
}

func TestLookupOrganizationsTrailingPeriodAndAmbiguityOnSQLite(t *testing.T) {
    repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "organization-lookup.db"))
    if err != nil { t.Fatal(err) }
    defer func() { _ = repo.Close() }()
    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
    defer cancel()

    first, err := repo.CreateAsset(ctx, &oamorg.Organization{
        ID: "synthetic-acme-holdings", Name: "Acme Holdings Inc.",
    })
    if err != nil { t.Fatal(err) }
    adapter := Adapter{Repo: repo}

    withoutPeriod, err := adapter.LookupOrganizations(ctx, "Acme Holdings Inc", 10)
    if err != nil || len(withoutPeriod) != 1 || withoutPeriod[0].ID != first.ID {
        t.Fatalf("trailing-period fallback failed: matches=%+v err=%v", withoutPeriod, err)
    }
    withPeriod, err := adapter.LookupOrganizations(ctx, "Acme Holdings Inc.", 10)
    if err != nil || len(withPeriod) != 1 || withPeriod[0].ID != first.ID {
        t.Fatalf("exact-name lookup failed: matches=%+v err=%v", withPeriod, err)
    }
    missing, err := adapter.LookupOrganizations(ctx, "Unknown Demo Corp.", 10)
    if err != nil || len(missing) != 0 {
        t.Fatalf("unknown entity should be no-match: matches=%+v err=%v", missing, err)
    }

    // If two distinct assets differ only by final punctuation, do NOT
    // silently select one identity. The planner must surface ambiguity.
    second, err := repo.CreateAsset(ctx, &oamorg.Organization{
        ID: "synthetic-acme-separate", Name: "Acme Holdings Inc",
    })
    if err != nil { t.Fatal(err) }
    ambiguous, err := adapter.LookupOrganizations(ctx, "Acme Holdings Inc", 10)
    if err != nil || len(ambiguous) != 2 {
        t.Fatalf("expected two ambiguous organizations, got=%+v err=%v", ambiguous, err)
    }
    matched := map[string]bool{}
    for _, asset := range ambiguous { matched[asset.ID] = true }
    if !matched[first.ID] || !matched[second.ID] {
        t.Fatalf("ambiguous lookup omitted one entity: %+v", ambiguous)
    }
}
