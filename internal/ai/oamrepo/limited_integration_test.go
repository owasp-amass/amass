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
    oamurl "github.com/owasp-amass/open-asset-model/url"
    oamgen "github.com/owasp-amass/open-asset-model/general"
    oamorg "github.com/owasp-amass/open-asset-model/org"
    "github.com/owasp-amass/amass/v5/internal/ai"
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

func TestResolveOrganizationNativeIdentifiersAndSourcedAliasSQLite(t *testing.T) {
    repo,err:=assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(),"resolution.db"))
    if err!=nil {t.Fatal(err)}
    defer func(){_ = repo.Close()}()
    ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
    defer cancel()
    primary,err:=repo.CreateAsset(ctx,&oamorg.Organization{
        ID:"acme-holdings",Name:"Acme Holdings Inc.",LegalName:"Acme Holdings Incorporated",
        Jurisdiction:"US-NY",RegistrationID:"REG-100",
    })
    if err!=nil{t.Fatal(err)}
    secondary,err:=repo.CreateAsset(ctx,&oamorg.Organization{
        ID:"acme-holdings-uk",Name:"Acme Holdings Inc.",LegalName:"Acme Holdings UK Ltd.",
        Jurisdiction:"GB",RegistrationID:"REG-100",
    })
    if err!=nil{t.Fatal(err)}
    a:=Adapter{Repo:repo,Aliases:[]ai.OrganizationAlias{
        {Alias:"Acme Group",UniqueID:"acme-holdings",Source:"curated-registry-record-001",Jurisdiction:"US-NY"},
    }}
    cases:=[]struct{name string;q ai.OrganizationQuery;status string;wantID string}{
        {"legal name",ai.OrganizationQuery{LegalName:"Acme Holdings Incorporated"},"matched",primary.ID},
        {"unique id",ai.OrganizationQuery{UniqueID:"acme-holdings"},"matched",primary.ID},
        {"registration id",ai.OrganizationQuery{RegistrationID:"REG-100",Jurisdiction:"GB"},"matched",secondary.ID},
        {"alias",ai.OrganizationQuery{Name:"Acme Group"},"matched",primary.ID},
        {"ambiguous display",ai.OrganizationQuery{Name:"Acme Holdings Inc"},"ambiguous",""},
        {"jurisdiction display",ai.OrganizationQuery{Name:"Acme Holdings Inc",Jurisdiction:"US-NY"},"matched",primary.ID},
        {"unknown",ai.OrganizationQuery{Name:"Unknown Corp."},"not_found",""},
    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            res,err:=a.ResolveOrganizations(ctx,tc.q,10)
            if err!=nil{t.Fatal(err)}
            if res.Status!=tc.status{t.Fatalf("status=%s expected=%s candidates=%+v",res.Status,tc.status,res.Candidates)}
            if tc.wantID!="" && (len(res.Candidates)!=1 || res.Candidates[0].Asset.ID!=tc.wantID){
                t.Fatalf("wrong resolved entity: %+v",res)
            }
            if tc.name=="alias" && (len(res.Candidates[0].Matches)!=1 ||
                res.Candidates[0].Matches[0].Source!="curated-registry-record-001") {
                t.Fatalf("alias source not recorded: %+v",res.Candidates)
            }
        })
    }
}

func TestResolveFQDNAndURLOnSQLite(t *testing.T){
	repo,err:=assetdb.New(sqlite3.SQLite,filepath.Join(t.TempDir(),"resolve-assets.db"))
	if err!=nil{t.Fatal(err)}
	defer func(){_ = repo.Close()}()
	ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
	defer cancel()
	fqdn,err:=repo.CreateAsset(ctx,&oamdns.FQDN{Name:"test.example"})
	if err!=nil{t.Fatal(err)}
	url,err:=repo.CreateAsset(ctx,&oamurl.URL{Raw:"https://test.example/",Scheme:"https",Host:"test.example",Path:"/"})
	if err!=nil{t.Fatal(err)}
	adapter:=Adapter{Repo:repo}
	cases:=[]struct{selector ai.AssetSelector;id string}{
		{ai.AssetSelector{Type:"FQDN",Field:"name",Value:"test.example"},fqdn.ID},
		{ai.AssetSelector{Type:"FQDN",Field:"name",Value:"TEST.EXAMPLE."},fqdn.ID},
		{ai.AssetSelector{Type:"URL",Field:"url",Value:"https://test.example/"},url.ID},
		{ai.AssetSelector{Type:"URL",EntityID:url.ID},url.ID},
	}
	for _,tc:=range cases {
		got,err:=adapter.ResolveAsset(ctx,tc.selector,10)
		if err!=nil || got.Status!="matched" || len(got.Candidates)!=1 || got.Candidates[0].Asset.ID!=tc.id{
			t.Fatalf("selector=%+v result=%+v err=%v",tc.selector,got,err)
		}
	}
	if _,err:=adapter.ResolveAsset(ctx,ai.AssetSelector{Type:"FQDN",Field:"unknown",Value:"x"},10);err==nil{
		t.Fatal("invalid selector field accepted")
	}
}
