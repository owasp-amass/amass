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
)

// This runs in paired-branch CI against the asset-db feature branch.
// The currently released asset-db may not have the bounded API yet.
func TestAdapterBoundedTraversalOnSQLite(t *testing.T) {
    repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "bounded-adapter.db"))
    if err != nil { t.Fatal(err) }
    defer repo.Close()
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
