// SPDX-License-Identifier: Apache-2.0
package oamrepo

import (
 "context"
 "path/filepath"
 "testing"

 "github.com/owasp-amass/amass/v5/internal/ai"
 assetdb "github.com/owasp-amass/asset-db"
 "github.com/owasp-amass/asset-db/repository/sqlite3"
 dbt "github.com/owasp-amass/asset-db/types"
 "github.com/owasp-amass/open-asset-model/general"
 "github.com/owasp-amass/open-asset-model/org"
)

func TestEdgeProvenanceDoesNotAliasEntityTagsOnSQLite(t *testing.T){
 ctx:=context.Background()
 path:=filepath.Join(t.TempDir(),"collision-fixture.db")
 db,err:=assetdb.New(sqlite3.SQLite,path)
 if err!=nil{t.Fatal(err)}
 defer db.Close()
 parent,err:=db.CreateAsset(ctx,&org.Organization{ID:"synthetic-parent",Name:"Synthetic Parent"})
 if err!=nil{t.Fatal(err)}
 child,err:=db.CreateAsset(ctx,&org.Organization{ID:"synthetic-child",Name:"Synthetic Child"})
 if err!=nil{t.Fatal(err)}
 edge,err:=db.CreateEdge(ctx,&dbt.Edge{
  Relation:&general.SimpleRelation{Name:"subsidiary"},
  FromEntity:parent,ToEntity:child,
 })
 if err!=nil{t.Fatal(err)}
 if _,err:=db.CreateEntityProperty(ctx,parent,&general.SourceProperty{Source:"synthetic-asset-source",Confidence:40});err!=nil{t.Fatal(err)}
 if _,err:=db.CreateEdgeProperty(ctx,edge,&general.SourceProperty{Source:"synthetic-edge-source",Confidence:90});err!=nil{t.Fatal(err)}
 adapter:=Adapter{Repo:db}
 got,err:=adapter.EdgeEvidence(ctx,edge.ID,8)
 if err!=nil{t.Fatal(err)}
 if len(got)!=1||got[0].SourceID!="synthetic-edge-source"||got[0].SubjectID!=edge.ID{
  t.Fatalf("edge tags misattributed to asset ID: %+v (asset ID %s, edge ID %s)",got,parent.ID,edge.ID)
 }
 dossier,err:=ai.EvaluatePathEvidence(ctx,adapter,ai.DefaultLimits(),[]ai.PlanMatch{{
  Nodes:[]ai.Asset{{ID:parent.ID,Type:"Organization"},{ID:child.ID,Type:"Organization"}},
  Edges:[]ai.Relation{{ID:edge.ID,FromID:parent.ID,ToID:child.ID,Label:"subsidiary",Type:"SimpleRelation"}},
 }})
 if err!=nil{t.Fatal(err)}
 if len(dossier.Paths)!=1||len(dossier.Paths[0].Edges)!=1||dossier.Paths[0].Edges[0].Status!="single_source"{
  t.Fatalf("database-backed edge dossier misclassified: %+v",dossier)
 }
 t.Logf("SQLite asset ID=%s edge ID=%s exact edge source=%s",parent.ID,edge.ID,got[0].SourceID)
}
