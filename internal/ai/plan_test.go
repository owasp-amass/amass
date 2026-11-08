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
func (c planCatalog) SearchFields() []AssetSearchSchema {
	return []AssetSearchSchema{
		{Type:"Organization",Fields:[]string{"name","legal_name","unique_id"}},
		{Type:"URL",Fields:[]string{"url"}},
		{Type:"FQDN",Fields:[]string{"name"}},
	}
}

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

func (g plannedGraph) ResolveAsset(_ context.Context, selector AssetSelector, _ int)(AssetResolution,error){
	result:=AssetResolution{Query:selector,Status:"not_found",Candidates:[]OrganizationCandidate{}}
	for _,asset:=range g.assets {
		if asset.Type!=selector.Type {continue}
		if selector.EntityID==asset.ID ||
			selector.Type=="URL" && selector.Field=="url" && selector.Value==asset.Key ||
			selector.Type=="FQDN" && selector.Field=="name" && selector.Value==asset.Key {
			result.Candidates=append(result.Candidates,OrganizationCandidate{Asset:asset,Matches:[]ResolutionMatch{{Field:selector.Field,Value:selector.Value}}})
		}
	}
	if len(result.Candidates)==1{result.Status="matched"}else if len(result.Candidates)>1{result.Status="ambiguous"}
	return result,nil
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
			"fqdn-tech": {ID: "fqdn-tech", Type: "FQDN", Key: "tech.acme.example", Content: map[string]any{"name":"tech.acme.example"}},
		},
		links: []Relation{
			{ID: "e1", FromID: "parent", ToID: "tech", Label: "subsidiary", Type: "SimpleRelation"},
			{ID: "e2", FromID: "parent", ToID: "europe", Label: "subsidiary", Type: "SimpleRelation"},
			{ID: "e3", FromID: "tech", ToID: "website-tech", Label: "website", Type: "SimpleRelation"},
			{ID: "e4", FromID: "europe", ToID: "website-europe", Label: "website", Type: "SimpleRelation"},
			{ID:"e5",FromID:"website-tech",ToID:"fqdn-tech",Label:"domain",Type:"SimpleRelation"},
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
	if err!=nil || !result.Incomplete || !strings.Contains(result.Answer,"No asset matched") {
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

func TestFQDNAsRootAndIncomingURLDomainEdge(t *testing.T){
	model:=&plannerModel{replies:[]string{`{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"hops":[{"direction":"in","label":"domain","relation_type":"SimpleRelation","destination_type":"URL"}]}`}}
	runner:=ToolRunner{Graph:examplePlannedGraph(),Limits:DefaultLimits(),Catalog:testOAMCatalog}
	out,err:=(Agent{Model:model,Runner:runner}).Ask(context.Background(),"Which URLs refer to the domain tech.acme.example?")
	if err!=nil || out.Incomplete || len(out.Matches)!=1 || out.Matches[0].Nodes[1].Key!="https://tech.acme.example/"{
		t.Fatalf("FQDN root error: %+v err=%v",out,err)
	}
	if out.AssetResolution==nil || out.AssetResolution.Status!="matched" {t.Fatalf("missing typed root resolution: %+v",out.AssetResolution)}
}
func TestURLAsRootAndOutgoingDomainEdge(t *testing.T){
	model:=&plannerModel{replies:[]string{
		`{"subject":{"type":"URL","field":"url","value":"https://tech.acme.example/"},"hops":[{"direction":"out","label":"domain","relation_type":"SimpleRelation","destination_type":"FQDN"}]}`}}
	runner:=ToolRunner{Graph:examplePlannedGraph(),Limits:DefaultLimits(),Catalog:testOAMCatalog}
	out,err:=(Agent{Model:model,Runner:runner}).Ask(context.Background(),"What FQDN is associated with https://tech.acme.example/?")
	if err!=nil || out.Incomplete || len(out.Matches)!=1 || out.Matches[0].Nodes[1].Key!="tech.acme.example"{
		t.Fatalf("URL root error: %+v err=%v",out,err)
	}
}
func TestGenericSelectorRejectsUnsupportedFields(t *testing.T){
	if err:=validatePlanWithSelectors(TypedPlan{
		Subject:PlanSubject{Type:"FQDN",Field:"domain",Value:"tech.acme.example"},
		Hops:[]PlanHop{{Direction:"in",Label:"domain",RelationType:"SimpleRelation",DestinationType:"URL"}},
	},testOAMCatalog.Relations(),testOAMCatalog.SearchFields(),DefaultLimits());err==nil{
		t.Fatal("unsupported FQDN selector should fail validation")
	}
}

// This reproduces the Ollama failure reported during a real FQDN-root query.
// The model reused the Organization "name" key for a non-Organization type;
// the indexed OAM selector catalog makes the correction unambiguous.
func TestPlannerNormalizesFQDNNameToIndexedSelector(t *testing.T){
	model:=&plannerModel{replies:[]string{
		`{"subject":{"type":"FQDN","name":"tech.acme.example"},"hops":[{"direction":"in","label":"domain","relation_type":"SimpleRelation","destination_type":"URL"}]}`,
	}}
	runner:=ToolRunner{Graph:examplePlannedGraph(),Limits:DefaultLimits(),Catalog:testOAMCatalog}
	out,err:=(Agent{Model:model,Runner:runner}).Ask(context.Background(),
		"Which URL assets have a domain relationship pointing to the FQDN tech.acme.example?")
	if err!=nil || out.Incomplete || model.calls!=1 || len(out.Matches)!=1 {
		t.Fatalf("FQDN normalization failed: %+v err=%v model calls=%d",out,err,model.calls)
	}
	if out.Plan.Subject.Field!="name" || out.Plan.Subject.Value!="tech.acme.example" || out.Plan.Subject.Name!=""{
		t.Fatalf("subject not canonicalized: %+v",out.Plan.Subject)
	}
	if out.Matches[0].Nodes[1].Key!="https://tech.acme.example/"{
		t.Fatalf("wrong URL destination: %+v",out.Matches)
	}
}

type inspectingPlannerModel struct {
	calls int
	requests [][]Message
	replies []string
}
func (m *inspectingPlannerModel) Generate(_ context.Context, messages []Message, _ []ToolSpec)(Response,error){
	m.requests=append(m.requests,append([]Message{},messages...))
	i:=m.calls
	m.calls++
	if i>=len(m.replies){i=len(m.replies)-1}
	return Response{Text:m.replies[i]},nil
}
func TestPlannerRetriesMissingTypedSelectorWithFocusedGuidance(t *testing.T){
	model:=&inspectingPlannerModel{replies:[]string{
		`{"subject":{"type":"FQDN"},"hops":[{"direction":"in","label":"domain","relation_type":"SimpleRelation","destination_type":"URL"}]}`,
		`{"subject":{"type":"FQDN","field":"name","value":"tech.acme.example"},"hops":[{"direction":"in","label":"domain","relation_type":"SimpleRelation","destination_type":"URL"}]}`,
	}}
	runner:=ToolRunner{Graph:examplePlannedGraph(),Limits:DefaultLimits(),Catalog:testOAMCatalog}
	out,err:=(Agent{Model:model,Runner:runner}).Ask(context.Background(),
		"Which URL assets have a domain relationship pointing to the FQDN tech.acme.example?")
	if err!=nil || out.Incomplete || len(out.Matches)!=1 || model.calls!=2 {
		t.Fatalf("focused retry failed: %+v err=%v calls=%d",out,err,model.calls)
	}
	if len(model.requests[1])<4 || !strings.Contains(model.requests[1][3].Text,"subject.field") ||
		!strings.Contains(model.requests[1][3].Text,"subject.value") {
		t.Fatalf("retry omitted selector-specific correction: %+v",model.requests[1])
	}
}

func TestNormalizationDoesNotGuessUnsupportedSelectors(t *testing.T){
	schema:=testOAMCatalog.SearchFields()
	cases:=[]PlanSubject{
		{Type:"URL",Name:"https://tech.acme.example/"},
		{Type:"FQDN",Field:"url",Name:"tech.acme.example"},
		{Type:"FQDN"},
	}
	for _,candidate:=range cases{
		got:=normalizePlannedSubject(candidate,schema)
		if got.Field!=candidate.Field || got.Value!=candidate.Value ||
			got.Name!=candidate.Name {
			t.Fatalf("should not infer selector for %+v, got %+v",candidate,got)
		}
	}
}

func TestPlanParserCanonicalizesSingleFieldObject(t *testing.T) {
    raw:=`{"subject":{"type":"URL","fields":{"url":"https://tech.acme.example/"}},"hops":[{"direction":"out","label":"domain","relation_type":"SimpleRelation","destination_type":"FQDN"}]}`
    p,err:=parseTypedPlanWithSelectors(raw,testOAMCatalog.SearchFields())
    if err!=nil{t.Fatal(err)}
    if p.Subject.Type!="URL" || p.Subject.Field!="url" || p.Subject.Value!="https://tech.acme.example/"{
        t.Fatalf("unexpected normalized subject: %+v",p.Subject)
    }
    if err:=validatePlanWithSelectors(p,testOAMCatalog.Relations(),testOAMCatalog.SearchFields(),DefaultLimits());err!=nil{
        t.Fatalf("normalized plan rejected: %v",err)
    }
}
func TestPlanParserRejectsUntrustedFieldCatalogs(t *testing.T) {
    tests:=[]string{
        `{"subject":{"type":"URL","fields":["url"]},"hops":[]}`,
        `{"subject":{"type":"URL","fields":{"url":"https://tech.acme.example/","scheme":"https"}},"hops":[]}`,
        `{"subject":{"type":"URL","fields":{"invented":"https://tech.acme.example/"}},"hops":[]}`,
        `{"subject":{"type":"URL","fields":{"url":"https://tech.acme.example/"},"unexpected":true},"hops":[]}`,
        `{"subject":{"type":"URL","fields":{"url":"https://tech.acme.example/"},"value":"https://elsewhere.example/" },"hops":[]}`,
    }
    for _,raw:=range tests{
        if _,err:=parseTypedPlanWithSelectors(raw,testOAMCatalog.SearchFields());err==nil{
            t.Fatalf("unexpectedly accepted malformed plan: %s",raw)
        }
    }
}
func TestPlannerCorrectsUnexpectedFields(t *testing.T){
    model:=&inspectingPlannerModel{replies:[]string{
        `{"subject":{"type":"URL","fields":["url"]},"hops":[{"direction":"out","label":"domain","relation_type":"SimpleRelation","destination_type":"FQDN"}]}`,
        `{"subject":{"type":"URL","field":"url","value":"https://tech.acme.example/"},"hops":[{"direction":"out","label":"domain","relation_type":"SimpleRelation","destination_type":"FQDN"}]}`,
    }}
    runner:=ToolRunner{Graph:examplePlannedGraph(),Limits:DefaultLimits(),Catalog:testOAMCatalog}
    got,err:=(Agent{Model:model,Runner:runner}).Ask(context.Background(),"What FQDN is associated with the URL https://tech.acme.example/?")
    if err!=nil || got.Incomplete || len(got.Matches)!=1 || model.calls!=2{
        t.Fatalf("retry failed: result=%+v err=%v calls=%d",got,err,model.calls)
    }
    retry:=model.requests[1][len(model.requests[1])-1].Text
    if !strings.Contains(retry,"unsupported key named fields") || !strings.Contains(retry,"singular field and value"){
        t.Fatalf("retry prompt not specific enough: %s",retry)
    }
}
