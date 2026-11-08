// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "context"
 "strings"
 "testing"
)

func TestAdaptiveQuestionUsesGenericRelationshipGoalAndSourceDossier(t *testing.T){
 model:=&plannerModel{replies:[]string{
  `{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["Organization"],"direction":"both","purpose":"connected","relationships":[{"source_type":"URL","label":"domain","relation_type":"SimpleRelation","destination_type":"FQDN"},{"source_type":"Organization","label":"website","relation_type":"SimpleRelation","destination_type":"URL"},{"source_type":"Organization","label":"subsidiary","relation_type":"SimpleRelation","destination_type":"Organization"}],"path_rule":"ordered"}`,
  `{"selected_asset_ids":["parent"]}`,
 }}
 runner:=ToolRunner{Graph:examplePlannedGraph(),Catalog:testOAMCatalog,Limits:DefaultLimits()}
 result,err:=(Agent{Model:model,Runner:runner}).AskAdaptive(context.Background(),
  "Which Organization has a path from tech.acme.example through domain then website then subsidiary relationships?",
  AdaptiveOptions{MaxDepth:8,MaxPathsPerAsset:3,GuidanceRounds:0})
 if err!=nil{t.Fatal(err)}
 if result.Goal==nil||result.Goal.PathRule!="ordered"||len(result.Goal.Relationships)!=3{
  t.Fatalf("model did not interpret exact relationship goal: %+v",result.Goal)
 }
 if len(result.Matches)!=1||len(result.Matches[0].Edges)!=3||result.Matches[0].Nodes[3].ID!="parent"{
  t.Fatalf("relationship constrained answer selected wrong path: %+v",result.Matches)
 }
 if result.EvidenceDossier==nil||len(result.EvidenceDossier.Paths)==0||!result.EvidenceIncomplete{
  t.Fatalf("missing source-level report or incorrect completeness for untagged edges: %+v",result)
 }
 if result.Incomplete{t.Fatal("database graph match should be complete separately from provenance incompleteness")}
 if !strings.Contains(result.Answer,"Source-level support is incomplete"){
  t.Fatalf("no source uncertainty warning: %s",result.Answer)
 }
 t.Logf("GOAL: rule=%s transitions=%d",result.Goal.PathRule,len(result.Goal.Relationships))
 t.Logf("ANSWER: %s",result.Answer)
 t.Logf("EVIDENCE: paths=%d status=%s",len(result.EvidenceDossier.Paths),result.EvidenceDossier.Paths[0].Status)
}

func TestAdaptiveGoalPlannerRepairsUnknownTaxonomyRelation(t *testing.T){
 model:=&plannerModel{replies:[]string{
  `{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["Organization"],"direction":"both","purpose":"connected","relationships":[{"source_type":"URL","label":"fabricated-ownership","relation_type":"SimpleRelation","destination_type":"FQDN"}],"path_rule":"any"}`,
  `{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"target_types":["Organization"],"direction":"both","purpose":"connected","relationships":[{"source_type":"URL","label":"domain","relation_type":"SimpleRelation","destination_type":"FQDN"}],"path_rule":"any"}`,
 }}
 agent:=Agent{Model:model,Runner:ToolRunner{Graph:examplePlannedGraph(),Catalog:testOAMCatalog,Limits:DefaultLimits()}}
 goal,err:=agent.planGoal(context.Background(),"What organizations relate to tech.acme.example through domain records?")
 if err!=nil{t.Fatal(err)}
 if model.calls!=2||len(goal.Relationships)!=1||goal.Relationships[0].Label!="domain"{
  t.Fatalf("invalid label not corrected: model_calls=%d goal=%+v",model.calls,goal)
 }
}
