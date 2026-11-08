// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type planCatalog []RelationshipSchema

func (c planCatalog) Relations() []RelationshipSchema { return c }

var testOAMCatalog = planCatalog{
	{SourceType: "Organization", Label: "subsidiary", RelationType: "SimpleRelation", DestinationType: "Organization"},
	{SourceType: "Organization", Label: "website", RelationType: "SimpleRelation", DestinationType: "URL"},
	{SourceType: "URL", Label: "domain", RelationType: "SimpleRelation", DestinationType: "FQDN"},
}

type plannedGraph struct{ fakeGraph }

func (g plannedGraph) LookupOrganizations(_ context.Context, name string, _ int) ([]Asset, error) {
	if name != "Acme Holdings Inc." {
		return []Asset{}, nil
	}
	return []Asset{g.assets["parent"]}, nil
}

func (g plannedGraph) ResolveOrganizations(_ context.Context, q OrganizationQuery, _ int) (OrganizationResolution,error) {
	result:=OrganizationResolution{Query:q,Status:"not_found",Candidates:[]OrganizationCandidate{}}
	if q.Name=="Acme Holdings Inc." || q.LegalName=="Acme Holdings Inc." || q.UniqueID=="synthetic-acme-holdings" {
		result.Status="matched"
		result.Candidates=[]OrganizationCandidate{{Asset:g.assets["parent"],Matches:[]ResolutionMatch{{Field:"name",Value:"Acme Holdings Inc."}}}}
	}
	return result,nil
}
func examplePlannedGraph() plannedGraph {
	return plannedGraph{fakeGraph{
		assets: map[string]Asset{
			"parent": {ID: "parent", Type: "Organization", Key: "synthetic-acme-holdings", Content: map[string]any{"name":"Acme Holdings Inc."}},
			"tech": {ID: "tech", Type: "Organization", Key: "synthetic-acme-tech", Content: map[string]any{"name":"Acme Technologies Ltd."}},
			"europe": {ID: "europe", Type: "Organization", Key: "synthetic-acme-europe", Content: map[string]any{"name":"Acme Europe GmbH"}},
			"website-tech": {ID: "website-tech", Type: "URL", Key: "https://tech.acme.example/", Content: map[string]any{"url":"https://tech.acme.example/"}},
			"website-europe": {ID: "website-europe", Type: "URL", Key: "https://eu.acme.example/", Content: map[string]any{"url":"https://eu.acme.example/"}},
		},
		links: []Relation{
			{ID: "e1", FromID: "parent", ToID: "tech", Label: "subsidiary", Type: "SimpleRelation"},
			{ID: "e2", FromID: "parent", ToID: "europe", Label: "subsidiary", Type: "SimpleRelation"},
			{ID: "e3", FromID: "tech", ToID: "website-tech", Label: "website", Type: "SimpleRelation"},
			{ID: "e4", FromID: "europe", ToID: "website-europe", Label: "website", Type: "SimpleRelation"},
		},
	}}
}

type plannerModel struct {
	calls int
	replies []string
}
func (m *plannerModel) Generate(_ context.Context, _ []Message, specs []ToolSpec) (Response, error) {
	if len(specs)>0 { return Response{}, nil }
	i:=m.calls
	m.calls++
	if i>=len(m.replies) {i=len(m.replies)-1}
	return Response{Text:m.replies[i]},nil
}
const websitePlan = `{"subject":{"type":"Organization","name":"Acme Holdings Inc."},"hops":[{"direction":"out","label":"subsidiary","relation_type":"SimpleRelation","destination_type":"Organization"},{"direction":"out","label":"website","relation_type":"SimpleRelation","destination_type":"URL"}]}`

func TestTypedPlannerMultiHopReturnsBothWebsites(t *testing.T){
	model:=&plannerModel{replies:[]string{websitePlan}}
	runner:=ToolRunner{Graph:examplePlannedGraph(),Limits:DefaultLimits(),Catalog:testOAMCatalog}
	out,err:=(Agent{Model:model,Runner:runner}).Ask(context.Background(),"What websites are associated with subsidiaries of Acme Holdings Inc.?")
	if err!=nil{t.Fatal(err)}
	if out.Incomplete || model.calls!=1 || out.ToolCalls!=4 || len(out.Matches)!=2 {
		t.Fatalf("unexpected planned result: %+v, calls %d",out,model.calls)
	}
	for _,s:=range []string{"Acme Technologies Ltd.","Acme Europe GmbH","https://tech.acme.example/","https://eu.acme.example/"}{
		if !strings.Contains(out.Answer,s) {t.Errorf("missing %q from answer: %s",s,out.Answer)}
	}
	if out.Plan==nil || len(out.Plan.Hops)!=2 {t.Fatalf("missing typed plan: %+v",out.Plan)}
}

func TestPlannerRejectsInventedLabelBeforeDatabaseAccess(t *testing.T){
	p:=TypedPlan{Subject:PlanSubject{Type:"Organization",Name:"Acme Holdings Inc."},Hops:[]PlanHop{{Direction:"out",Label:"hosted-on",RelationType:"SimpleRelation",DestinationType:"URL"}}}
	if err:=validatePlan(p,testOAMCatalog,DefaultLimits());err==nil {t.Fatal("made-up label accepted")}
}

func TestPlannerCorrectsWrongLabels(t *testing.T){
	bad:=`{"subject":{"type":"Organization","name":"Acme Holdings Inc."},"hops":[{"direction":"out","label":"subsidiary","relation_type":"SimpleRelation","destination_type":"Organization"},{"direction":"out","label":"hosted-on","relation_type":"SimpleRelation","destination_type":"URL"}]}`
	m:=&plannerModel{replies:[]string{bad,websitePlan}}
	runner:=ToolRunner{Graph:examplePlannedGraph(),Limits:DefaultLimits(),Catalog:testOAMCatalog}
	result,err:=(Agent{Model:m,Runner:runner}).Ask(context.Background(),"Show subsidiary websites")
	if err!=nil || len(result.Matches)!=2 || m.calls!=2 {t.Fatalf("correction failed: %+v err=%v calls=%d",result,err,m.calls)}
}
func TestUnknownOrganizationIsIncompleteNotError(t *testing.T){
	m:=&plannerModel{replies:[]string{`{"subject":{"type":"Organization","name":"Unknown Corp."},"hops":[{"direction":"out","label":"subsidiary","relation_type":"SimpleRelation","destination_type":"Organization"}]}`}}
	runner:=ToolRunner{Graph:examplePlannedGraph(),Limits:DefaultLimits(),Catalog:testOAMCatalog}
	result,err:=(Agent{Model:m,Runner:runner}).Ask(context.Background(),"What subsidiaries does Unknown Corp. have?")
	if err!=nil || !result.Incomplete || !strings.Contains(result.Answer,"No Organization matched") {
		t.Fatalf("no-match response: %+v err=%v",result,err)
	}
}
func TestSchemaCatalogTool(t *testing.T){
	runner:=ToolRunner{Graph:examplePlannedGraph(),Limits:DefaultLimits(),Catalog:testOAMCatalog}
	raw,err:=runner.Run(context.Background(),"describe_oam_schema",json.RawMessage(`{"source_type":"Organization"}`))
	if err!=nil{t.Fatal(err)}
	var rows []RelationshipSchema
	if err:=json.Unmarshal(raw,&rows);err!=nil{t.Fatal(err)}
	if len(rows)!=2{t.Fatalf("expected two schema relations, got %d",len(rows))}
}
