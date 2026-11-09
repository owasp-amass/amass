// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "context"
 "fmt"
 "strings"
 "testing"
)

// Fixture uses exact stored edge orientation and unrelated graph neighbors.
// The same compiler operates across FQDN, URL, Organization and IPAddress.
type intentCatalog struct{
 rels []RelationshipSchema
 selectors []AssetSearchSchema
}
func(c intentCatalog)Relations()[]RelationshipSchema{return c.rels}
func(c intentCatalog)SearchFields()[]AssetSearchSchema{return c.selectors}

var typedIntentTestCatalog=intentCatalog{
 rels:[]RelationshipSchema{
  {SourceType:"URL",Label:"domain",RelationType:"SimpleRelation",DestinationType:"FQDN"},
  {SourceType:"Organization",Label:"website",RelationType:"SimpleRelation",DestinationType:"URL"},
  {SourceType:"FQDN",Label:"dns_record",RelationType:"BasicDNSRelation",DestinationType:"IPAddress"},
  {SourceType:"FQDN",Label:"node",RelationType:"SimpleRelation",DestinationType:"FQDN"},
 },
 selectors:[]AssetSearchSchema{
  {Type:"FQDN",Fields:[]string{"name"}},
  {Type:"URL",Fields:[]string{"url"}},
  {Type:"IPAddress",Fields:[]string{"address"}},
  {Type:"Organization",Fields:[]string{"name","legal_name"}},
 },
}

func typedIntentGraph()plannedGraph{
 g:=fakeGraph{assets:map[string]Asset{
  "host":{ID:"host",Type:"FQDN",Key:"tech.acme.example",Content:map[string]any{"name":"tech.acme.example"}},
  "site":{ID:"site",Type:"URL",Key:"https://tech.acme.example/",Content:map[string]any{"url":"https://tech.acme.example/"}},
  "company":{ID:"company",Type:"Organization",Key:"Acme Technologies Ltd.",Content:map[string]any{"name":"Acme Technologies Ltd."}},
  "ip":{ID:"ip",Type:"IPAddress",Key:"192.0.2.10",Content:map[string]any{"address":"192.0.2.10"}},
 }}
 g.links=[]Relation{
  {ID:"edge-domain",FromID:"site",ToID:"host",Label:"domain",Type:"SimpleRelation"},
  {ID:"edge-website",FromID:"company",ToID:"site",Label:"website",Type:"SimpleRelation"},
  {ID:"edge-ip",FromID:"host",ToID:"ip",Label:"dns_record",Type:"BasicDNSRelation"},
 }
 // These unrelated edges are deliberately numerous, to reproduce
 // match-limit starvation from indiscriminate guided exploration.
 for i:=0;i<35;i++{
  id:=fmt.Sprintf("noise-%02d",i)
  g.assets[id]=Asset{ID:id,Type:"FQDN",Key:fmt.Sprintf("noise-%02d.acme.example",i)}
  g.links=append(g.links,Relation{ID:"noise-edge-"+id,FromID:"host",ToID:id,Label:"node",Type:"SimpleRelation"})
 }
 return plannedGraph{fakeGraph:g}
}

func TestTypedRelationIntentUsesIncomingOAMEdgesAndNoLLM(t *testing.T){
 q:="Which URL assets are connected to tech.acme.example via domain relationships?"
 compiled,ok:=deterministicTypedRelationIntent(q,typedIntentTestCatalog)
 if !ok||len(compiled.Hops)!=1||compiled.Hops[0].Direction!="in"||
  compiled.Hops[0].DestinationType!="URL"||compiled.Hops[0].RelationType!="SimpleRelation"{
  t.Fatalf("failed to compile exact incoming OAM domain relation: %+v ok=%t",compiled,ok)
 }
 model:=&plannerModel{}
 result,err:=(Agent{Model:model,Runner:ToolRunner{
  Graph:typedIntentGraph(),Catalog:typedIntentTestCatalog,Limits:DefaultLimits(),
 }}).AskAdaptive(context.Background(),q,AdaptiveOptions{GuidanceRounds:2})
 if err!=nil{t.Fatal(err)}
 if model.calls!=0{t.Fatalf("schema-grounded query invoked model %d times",model.calls)}
 if result.Search==nil||result.Search.Truncated||result.Search.Mode!="typed_relation_inventory"||
  len(result.Matches)!=1||result.Matches[0].Nodes[len(result.Matches[0].Nodes)-1].ID!="site"{
  t.Fatalf("incoming domain lookup unexpectedly consumed unrelated graph paths: %+v",result)
 }
 if len(result.AnswerGroups)!=1||!strings.Contains(result.Answer,"https://tech.acme.example/")||
  !strings.Contains(result.Answer,"in:domain/SimpleRelation"){
  t.Fatalf("lost observed URL relationship semantics: %+v",result)
 }
 if result.EvidenceDossier==nil||len(result.EvidenceDossier.Paths)!=1{t.Fatalf("missing provenance: %+v",result.EvidenceDossier)}
}

func TestTypedRelationIntentTwoHopsAcrossThreeAssetTypes(t *testing.T){
 q:="Which organizations are connected to tech.acme.example via domain and website relationships?"
 intent,ok:=deterministicTypedRelationIntent(q,typedIntentTestCatalog)
 if !ok||len(intent.Hops)!=2||
  intent.Hops[0].Direction!="in"||intent.Hops[1].Direction!="in"||
  intent.Hops[1].DestinationType!="Organization"{
  t.Fatalf("expected FQDN <-domain- URL <-website- Organization, got %+v (ok=%v)",intent,ok)
 }
 g:=typedIntentGraph()
 result,err:=searchTypedRelationIntent(context.Background(),g,DefaultLimits(),g.assets["host"],intent,AdaptiveOptions{})
 if err!=nil{t.Fatal(err)}
 if result.Truncated||len(result.Matches)!=1||len(result.Matches[0].Edges)!=2{
  t.Fatalf("typed two-hop path lost witness: %+v",result)
 }
 if result.Matches[0].Nodes[2].ID!="company"{t.Fatalf("wrong organization: %+v",result.Matches[0])}
}

func TestTypedRelationIntentUsesOtherRegisteredAssetTypes(t *testing.T){
 q:="Which IP addresses are connected to tech.acme.example via dns_record relationships?"
 intent,ok:=deterministicTypedRelationIntent(q,typedIntentTestCatalog)
 if !ok||len(intent.Hops)!=1||intent.Hops[0].Direction!="out"||
  intent.Hops[0].RelationType!="BasicDNSRelation"{
  t.Fatalf("did not preserve typed DNS relationship: %+v ok=%t",intent,ok)
 }
 g:=typedIntentGraph()
 result,err:=searchTypedRelationIntent(context.Background(),g,DefaultLimits(),g.assets["host"],intent,AdaptiveOptions{})
 if err!=nil||result.Truncated||len(result.Matches)!=1||result.Matches[0].Nodes[1].ID!="ip"{
  t.Fatalf("wrong IP match: result=%+v err=%v",result,err)
 }
}

func TestTypedRelationIntentPartialAnswersRemainHonest(t *testing.T){
 g:=typedIntentGraph()
 // A direct FQDN node query must be deliberately explicit about node edges.
 q:="Which FQDN assets are connected to tech.acme.example via node relationships?"
 intent,ok:=deterministicTypedRelationIntent(q,typedIntentTestCatalog)
 if !ok{t.Fatal("typed FQDN node query not recognized")}
 result,err:=searchTypedRelationIntent(context.Background(),g,DefaultLimits(),g.assets["host"],intent,AdaptiveOptions{MaxMatches:4})
 if err!=nil{t.Fatal(err)}
 if !result.Truncated||result.Reason!="match limit"||len(result.Matches)!=4||result.Exhausted{
  t.Fatalf("result must indicate limited inventory: %+v",result)
 }
 answer:=typedRelationAnswer(g.assets["host"],intent,result.Matches,result.Truncated,result.Reason)
 if !strings.Contains(answer,"Found 4 FQDN asset(s)")||!strings.Contains(answer,"Results are partial"){
  t.Fatalf("partial results were hidden: %s",answer)
 }
}

func TestTypedRelationIntentRejectsAmbiguityAndInventedTaxonomy(t *testing.T){
 bad:=[]string{
  "Which URLs are connected to tech.acme.example?",
  "Which organizations own tech.acme.example via domain relationships?",
  "Which URLs are connected to tech.acme.example and other.example via domain relationships?",
  "Which URLs are connected to user@tech.acme.example via domain relationships?",
  "Which URLs are connected to tech.acme.example via fabricated relationships?",
 }
 for _,q:=range bad{
  if _,ok:=deterministicTypedRelationIntent(q,typedIntentTestCatalog);ok{
   t.Errorf("ambiguous or fabricated relation incorrectly grounded: %q",q)
  }
 }
 twoWays:=typedIntentTestCatalog
 twoWays.rels=append(append([]RelationshipSchema(nil),twoWays.rels...),
  RelationshipSchema{SourceType:"FQDN",Label:"domain",RelationType:"SimpleRelation",DestinationType:"URL"})
 if _,ok:=deterministicTypedRelationIntent("Which URLs are connected to tech.acme.example via domain relationships?",twoWays);ok{
  t.Fatal("ambiguous opposite edge directions must fall back to semantic planning")
 }
}

func TestTypedRelationIntentFirstHopEmptyDoesNotInventOrganizationAbsence(t *testing.T){
 g:=typedIntentGraph()
 // Simulate FQDNs collected by subs, but without the URL -> domain edge.
 edges:=make([]Relation,0,len(g.links))
 for _,edge:=range g.links{if edge.Label!="domain"{edges=append(edges,edge)}}
 g.links=edges
 model:=&plannerModel{}
 q:="Which organizations are connected to tech.acme.example via domain and website relationships?"
 got,err:=(Agent{Model:model,Runner:ToolRunner{Graph:g,Catalog:typedIntentTestCatalog,Limits:DefaultLimits()}}).
  AskAdaptive(context.Background(),q,AdaptiveOptions{})
 if err!=nil{t.Fatal(err)}
 if model.calls!=0{t.Fatalf("explicit typed relation unexpectedly called model: %d",model.calls)}
 if got.Search==nil||got.Search.Truncated||!got.Search.Exhausted||got.Incomplete||len(got.Matches)!=0{
  t.Fatalf("zero accepted first hop must be a completed, empty typed search: %+v",got)
 }
 hops:=got.Search.HopDiagnostics
 if len(hops)!=1||hops[0].Hop!=1||hops[0].Direction!="in"||
  hops[0].Label!="domain"||hops[0].QueriedPaths!=1||hops[0].ReturnedEdges!=0||hops[0].OutputPaths!=0{
  t.Fatalf("incorrect missing first hop trace: %+v",hops)
 }
 if !strings.Contains(got.Answer,"first empty relationship hop was 1")||
  !strings.Contains(got.Answer,"subsequent hop(s) were not evaluated")||
  !strings.Contains(got.Answer,"other OAM relationship paths"){
  t.Fatalf("zero organization answer must explain missing URL/domain bridge: %s",got.Answer)
 }
 for _,event:=range got.Trace{
  if event.Stage=="path_selection"&&event.Incomplete{
   t.Fatalf("completed empty deterministic search incorrectly marked incomplete: %+v",event)
  }
 }
}

func TestTypedRelationIntentReportsSecondHopWhenWebsiteRelationMissing(t *testing.T){
 g:=typedIntentGraph()
 edges:=make([]Relation,0,len(g.links))
 for _,edge:=range g.links{if edge.Label!="website"{edges=append(edges,edge)}}
 g.links=edges
 q:="Which organizations are connected to tech.acme.example via domain and website relationships?"
 intent,ok:=deterministicTypedRelationIntent(q,typedIntentTestCatalog)
 if !ok{t.Fatal("expected a two-hop typed intent")}
 result,err:=searchTypedRelationIntent(context.Background(),g,DefaultLimits(),g.assets["host"],intent,AdaptiveOptions{})
 if err!=nil{t.Fatal(err)}
 if len(result.HopDiagnostics)!=2{t.Fatalf("expected attempted website hop, got %+v",result.HopDiagnostics)}
 first,second:=result.HopDiagnostics[0],result.HopDiagnostics[1]
 if first.ReturnedEdges!=1||first.OutputPaths!=1||second.QueriedPaths!=1||
  second.ReturnedEdges!=0||second.Label!="website"||result.Truncated{
  t.Fatalf("did not distinguish first-hop success from second-hop failure: %+v",result.HopDiagnostics)
 }
 explanation:=typedRelationEmptyExplanation(result,intent)
 if !strings.Contains(explanation,"first empty relationship hop was 2")||
  strings.Contains(explanation,"subsequent hop(s)"){
  t.Fatalf("incorrect missing second hop explanation: %s",explanation)
 }
}
