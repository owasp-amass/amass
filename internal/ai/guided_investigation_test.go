// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "context"
 "fmt"
 "strings"
 "testing"
)

func TestGuidedInvestigationRequestsValidModelPriorities(t *testing.T){
 g:=fakeGraph{assets:map[string]Asset{"root":{ID:"root",Type:"Organization",Key:"root-org"}}}
 for i:=0;i<15;i++{
  id:=fmt.Sprintf("url-%02d",i)
  g.assets[id]=Asset{ID:id,Type:"URL",Key:"https://example.org/"+id}
  g.links=append(g.links,Relation{ID:fmt.Sprintf("e%02d",i),FromID:"root",ToID:id,Label:"website",Type:"SimpleRelation"})
 }
 model:=&plannerModel{replies:[]string{`{"preferred_labels":["website"],"priority_asset_ids":[]}`}}
 agent:=Agent{Model:model,Runner:ToolRunner{Graph:g,Catalog:testOAMCatalog,Limits:DefaultLimits()}}
 var investigation Investigation
 result,err:=agent.guidedInvestigation(context.Background(),
  "Which websites belong to this organization?",
  InvestigationGoal{Purpose:"connected",TargetTypes:[]string{"URL"},Direction:"both"},
  g.assets["root"],AdaptiveOptions{MaxDepth:2,MaxMatches:20,GuidanceRounds:1},&investigation)
 if err!=nil{t.Fatal(err)}
 if model.calls!=1 || len(investigation.Observations)!=1 || investigation.Observations[0].Tool!="guide_graph" {
  t.Fatalf("expected intermediate model guidance: calls=%d observations=%+v",model.calls,investigation.Observations)
 }
 if result.Truncated || !result.Exhausted || len(result.Matches)!=15 {
  t.Fatalf("guided traversal lost graph results: %+v",result)
 }
}

func TestGuidedInvestigationInvalidAdviceCannotInventGraphLabels(t *testing.T){
 g:=fakeGraph{assets:map[string]Asset{"root":{ID:"root",Type:"Organization",Key:"root-org"}}}
 for i:=0;i<15;i++{
  id:=fmt.Sprintf("url-%02d",i)
  g.assets[id]=Asset{ID:id,Type:"URL",Key:id}
  g.links=append(g.links,Relation{ID:fmt.Sprint(i),FromID:"root",ToID:id,Label:"website",Type:"SimpleRelation"})
 }
 model:=&plannerModel{replies:[]string{`{"preferred_labels":["nonexistent-ownership"],"priority_asset_ids":[]}`}}
 agent:=Agent{Model:model,Runner:ToolRunner{Graph:g,Catalog:testOAMCatalog,Limits:DefaultLimits()}}
 var inv Investigation
 result,err:=agent.guidedInvestigation(context.Background(),"List URLs",
  InvestigationGoal{Purpose:"connected",TargetTypes:[]string{"URL"},Direction:"both"},
  g.assets["root"],AdaptiveOptions{MaxDepth:2,MaxMatches:20,GuidanceRounds:1},&inv)
 if err!=nil{t.Fatal(err)}
 if len(inv.Observations)!=1 || !strings.Contains(inv.Observations[0].Error,"unknown OAM relationship label"){
  t.Fatalf("invalid advice not flagged: %+v",inv.Observations)
 }
 if len(result.Matches)!=15 || result.Truncated{t.Fatalf("invalid advice changed graph coverage: %+v",result)}
}
