// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "context"
 "testing"
)

// The real Qwen3 acceptance question previously needed ~98s of goal
// planning plus ~219s of route selection. Both inference calls are
// avoidable for this precise, explicitly constrained OAM query shape.
func TestExplicitOrganizationQuestionUsesZeroModelCalls(t *testing.T){
 model:=&plannerModel{replies:[]string{}}
 agent:=Agent{Model:model,Runner:ToolRunner{
  Graph:examplePlannedGraph(),Catalog:testOAMCatalog,Limits:DefaultLimits(),
 }}
 question:="Which organization is connected to tech.acme.example through website and domain relationships, and which witnessed route has better named source-tag coverage?"
 result,err:=agent.AskAdaptive(context.Background(),question,AdaptiveOptions{MaxDepth:8,GuidanceRounds:0})
 if err!=nil{t.Fatal(err)}
 if model.calls!=0{t.Fatalf("explicit goal and clear direct result should not invoke LLM, got %d model calls",model.calls)}
 if result.Goal==nil||result.Goal.PathRule!="all"||len(result.Goal.Relationships)!=2{
  t.Fatalf("wrong grounded OAM goal: %+v",result.Goal)
 }
 if result.Search==nil||result.Search.Truncated||len(result.Search.Matches)!=3{
  t.Fatalf("graph candidates incomplete: %+v",result.Search)
 }
 if len(result.Matches)!=1||result.Matches[0].Nodes[len(result.Matches[0].Nodes)-1].ID!="tech"{
  t.Fatalf("direct Organization should be only primary result: %+v",result.Matches)
 }
 if len(result.AnswerGroups)!=3||result.EvidenceDossier==nil||len(result.EvidenceDossier.Paths)!=3{
  t.Fatalf("indirect candidates or evidence discarded: groups=%+v dossier=%+v",result.AnswerGroups,result.EvidenceDossier)
 }
 stages:=map[string]string{}
 for _,event:=range result.Trace{stages[event.Stage]=event.Detail}
 if stages["goal_planning"]!="deterministic_schema_grounding"||stages["path_selection"]!="deterministic_destination_grouping"{
  t.Fatalf("missing model-bypass stage tracing: %+v",result.Trace)
 }
 t.Logf("FAST PATH: model_calls=%d, graph_candidates=%d, answer_groups=%d, selected=%d, planning=%s, selection=%s",
  model.calls,len(result.Search.Matches),len(result.AnswerGroups),len(result.Matches),stages["goal_planning"],stages["path_selection"])
}

func TestDeterministicGoalFastPathFailsClosedForAmbiguity(t *testing.T){
 cases:=[]string{
  "Which organization is connected to https://tech.acme.example/ via domain and website relationships?",
  "Which organization is connected to tech.acme.example and other.example via domain and website relationships?",
  "Which organization is connected to user@tech.acme.example via domain and website relationships?",
  "What is the highest parent organization connected to tech.acme.example via domain and website relationships?",
  "Which organization is connected to tech.acme.example?",
 }
 for _,question:=range cases{
  _,ok:=deterministicExplicitOrganizationGoal(question,testOAMCatalog)
  if ok{t.Errorf("ambiguous question incorrectly bypassed model: %s",question)}
 }
}
