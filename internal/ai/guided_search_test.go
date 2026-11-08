// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "context"
 "errors"
 "fmt"
 "strings"
 "testing"
)

func diamondGuidedGraph() fakeGraph{
 return fakeGraph{assets:map[string]Asset{
  "f":{ID:"f",Type:"FQDN",Key:"demo.example"},
  "u1":{ID:"u1",Type:"URL",Key:"https://demo.example/a"},
  "u2":{ID:"u2",Type:"URL",Key:"https://demo.example/b"},
  "org":{ID:"org",Type:"Organization",Key:"synthetic-org"},
 },links:[]Relation{
  {ID:"d1",FromID:"u1",ToID:"f",Label:"domain",Type:"SimpleRelation"},
  {ID:"d2",FromID:"u2",ToID:"f",Label:"domain",Type:"SimpleRelation"},
  {ID:"w1",FromID:"org",ToID:"u1",Label:"website",Type:"SimpleRelation"},
  {ID:"w2",FromID:"org",ToID:"u2",Label:"website",Type:"SimpleRelation"},
 }}
}

func TestGuidedSearchRetainsAlternativePathsToSameAsset(t *testing.T){
 limits:=DefaultLimits()
 e,err:=NewGuidedExplorer(context.Background(),diamondGuidedGraph(),testOAMCatalog,limits,GuidedSearchRequest{
  GraphSearchRequest:GraphSearchRequest{StartID:"f",TargetTypes:[]string{"Organization"},MaxDepth:5},
  MaxPathsPerAsset:3,
 })
 if err!=nil{t.Fatal(err)}
 for{
  done,err:=e.Advance(context.Background(),1)
  if err!=nil{t.Fatal(err)}
  if done{break}
 }
 result:=e.Result()
 if len(result.Matches)!=2 || !result.Exhausted || result.Truncated || result.AlternativeMatches!=1 {
  t.Fatalf("expected two complete alternative paths: %+v",result)
 }
 a,b:=result.Matches[0],result.Matches[1]
 if len(a.Edges)!=2 || len(b.Edges)!=2 || a.PathID==b.PathID || a.Nodes[2].ID!="org" || b.Nodes[2].ID!="org"{
  t.Fatalf("distinct, witnessed paths to same organization not retained: %+v",result.Matches)
 }
 if result.VisitedNodes!=4 || result.VisitedEdges!=4 {t.Fatalf("unexpected coverage: %+v",result)}
}

func TestGuidedSearchCannotUseInventedRelationPriorities(t *testing.T){
 e,err:=NewGuidedExplorer(context.Background(),diamondGuidedGraph(),testOAMCatalog,DefaultLimits(),GuidedSearchRequest{
  GraphSearchRequest:GraphSearchRequest{StartID:"f",TargetTypes:[]string{"Organization"}},
 })
 if err!=nil{t.Fatal(err)}
 if err:=e.Focus([]string{"invented-ownership-relation"},nil);err==nil{t.Fatal("invented relation label accepted")}
 if err:=e.Focus([]string{"website"},[]string{"not-in-frontier"});err==nil{t.Fatal("invented asset ID accepted")}
 if err:=e.Focus([]string{"website"},[]string{"f"});err!=nil{t.Fatal(err)}
}

func TestGuidedSearchMarksAlternativeRouteLimitAsPartial(t *testing.T){
 e,err:=NewGuidedExplorer(context.Background(),diamondGuidedGraph(),testOAMCatalog,DefaultLimits(),GuidedSearchRequest{
  GraphSearchRequest:GraphSearchRequest{StartID:"f",TargetTypes:[]string{"Organization"},MaxDepth:5},
  MaxPathsPerAsset:1,
 })
 if err!=nil{t.Fatal(err)}
 _,err=e.Advance(context.Background(),0)
 if err!=nil{t.Fatal(err)}
 r:=e.Result()
 if len(r.Matches)!=1 || !r.Truncated || r.Exhausted || r.AlternativePathsSkipped<1 {
  t.Fatalf("alternative path budget must report partial coverage: %+v",r)
 }
}

func TestGuidedSearchHonorsStageAndExpansionLimits(t *testing.T){
 e,err:=NewGuidedExplorer(context.Background(),diamondGuidedGraph(),testOAMCatalog,DefaultLimits(),GuidedSearchRequest{
  GraphSearchRequest:GraphSearchRequest{StartID:"f",TargetTypes:[]string{"Organization"},MaxDepth:5},
  MaxExpansions:1,
 })
 if err!=nil{t.Fatal(err)}
 done,err:=e.Advance(context.Background(),1)
 if err!=nil||done{t.Fatalf("expected pending frontier: done=%t error=%v",done,err)}
 if len(e.Pending(10))==0{t.Fatal("no pending frontier")}
 done,err=e.Advance(context.Background(),1)
 if err!=nil||!done{t.Fatalf("budget should stop next stage: done=%t error=%v",done,err)}
 r:=e.Result()
 if !r.Truncated || !strings.Contains(r.Reason,"expansion") || r.ExpandedPaths!=1 {t.Fatalf("expansion limit not enforced: %+v",r)}
}

func TestGuidedSearchSupportsMoreThanTenHops(t *testing.T){
 graph:=fakeGraph{assets:map[string]Asset{},links:[]Relation{}}
 catalog:=planCatalog{{SourceType:"FQDN",Label:"related",RelationType:"SimpleRelation",DestinationType:"Service"},
  {SourceType:"Service",Label:"related",RelationType:"SimpleRelation",DestinationType:"FQDN"}}
 for i:=0;i<=15;i++{
  id:=fmt.Sprintf("a%02d",i)
  typ:="FQDN"
  if i%2==1 {typ="Service"}
  graph.assets[id]=Asset{ID:id,Type:typ,Key:id}
  if i>0{graph.links=append(graph.links,Relation{ID:fmt.Sprintf("e%02d",i),FromID:fmt.Sprintf("a%02d",i-1),ToID:id,Label:"related",Type:"SimpleRelation"})}
 }
 e,err:=NewGuidedExplorer(context.Background(),graph,catalog,DefaultLimits(),GuidedSearchRequest{
  GraphSearchRequest:GraphSearchRequest{StartID:"a00",TargetTypes:[]string{"Service"},MaxDepth:15,MaxMatches:20},
  MaxPathsPerAsset:2,MaxExpansions:100,
 })
 if err!=nil{t.Fatal(err)}
 done,err:=e.Advance(context.Background(),0)
 if err!=nil||!done{t.Fatalf("long guided path error: done=%t err=%v",done,err)}
 r:=e.Result()
 found:=false
 for _,p:=range r.Matches{if len(p.Edges)==15&&p.Nodes[len(p.Nodes)-1].ID=="a15"{found=true}}
 if !found||r.Truncated||!r.Exhausted{t.Fatalf("15-hop graph path not found: %+v",r)}
}

func TestGuidedSelectionRequiresPathIDForAmbiguousAsset(t *testing.T){
 e,err:=NewGuidedExplorer(context.Background(),diamondGuidedGraph(),testOAMCatalog,DefaultLimits(),GuidedSearchRequest{
  GraphSearchRequest:GraphSearchRequest{StartID:"f",TargetTypes:[]string{"Organization"},MaxDepth:5},
 })
 if err!=nil{t.Fatal(err)}
 _,err=e.Advance(context.Background(),0);if err!=nil{t.Fatal(err)}
 paths:=e.Result().Matches
 model:=&plannerModel{replies:[]string{
  `{"selected_asset_ids":["org"]}`,
  `{"selected_path_ids":["not-a-witnessed-path"]}`,
 }}
 _,err=(Agent{Model:model}).chooseAdaptivePaths(context.Background(),"Which organization?",InvestigationGoal{Purpose:"connected"},paths)
 if err==nil||!strings.Contains(err.Error(),"not witnessed"){t.Fatalf("ambiguous or invented selection accepted: %v",err)}
}

func TestGuidedExplorationStopsOnContextCancellation(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background())
 e,err:=NewGuidedExplorer(ctx,diamondGuidedGraph(),testOAMCatalog,DefaultLimits(),GuidedSearchRequest{
  GraphSearchRequest:GraphSearchRequest{StartID:"f",TargetTypes:[]string{"Organization"}},
 })
 if err!=nil{t.Fatal(err)}
 cancel()
 _,err=e.Advance(ctx,0)
 if !errors.Is(err,context.Canceled){t.Fatalf("context cancellation not respected: %v",err)}
}
