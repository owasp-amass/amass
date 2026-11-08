// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type namedGraph struct{ fakeGraph }
func (g namedGraph) LookupOrganizations(_ context.Context, name string, _ int) ([]Asset, error) {
	if name != "Acme Holdings Inc." {
		return nil, nil
	}
	return []Asset{{ID: "a", Type: "Organization", Key: "synthetic-acme-holdings", Content: map[string]any{"name": name}}}, nil
}
type noCallModel struct{ calls int }
func (m *noCallModel) Generate(_ context.Context, _ []Message, _ []ToolSpec) (Response, error) {
	m.calls++
	return Response{Text: "I found no subsidiaries."}, nil
}
func TestDirectSubsidiaryQuestionIsDatabaseGroundedWithoutModel(t *testing.T) {
	g := namedGraph{fakeGraph{assets: map[string]Asset{
		"a": {ID: "a", Type: "Organization", Key: "synthetic-acme-holdings"},
		"b": {ID: "b", Type: "Organization", Key: "synthetic-acme-tech", Content: map[string]any{"name":"Acme Technologies Ltd."}},
		"c": {ID: "c", Type: "Organization", Key: "synthetic-acme-europe", Content: map[string]any{"name":"Acme Europe GmbH"}},
	}, links: []Relation{
		{ID: "1", FromID: "a", ToID: "b", Label: "subsidiary"},
		{ID: "2", FromID: "a", ToID: "c", Label: "subsidiary"},
	}}}
	model := &noCallModel{}
	res, err := (Agent{Model:model, Runner:ToolRunner{Graph:g, Limits:DefaultLimits()}}).Ask(context.Background(), "What subsidiaries does Acme Holdings Inc. have?")
	if err != nil { t.Fatal(err) }
	if res.Incomplete || res.ToolCalls != 2 || model.calls != 0 ||
		!strings.Contains(res.Answer, "Acme Technologies Ltd.") ||
		!strings.Contains(res.Answer, "Acme Europe GmbH") {
		t.Fatalf("unexpected deterministic result: %+v, model calls %d", res, model.calls)
	}
}
func TestUnknownOrganizationDoesNotImplyNoSubsidiaries(t *testing.T) {
	g := namedGraph{fakeGraph{assets: map[string]Asset{}}}
	model := &noCallModel{}
	res, err := (Agent{Model:model, Runner:ToolRunner{Graph:g, Limits:DefaultLimits()}}).Ask(context.Background(), "What subsidiaries does Unknown Inc. have?")
	if err != nil { t.Fatal(err) }
	if !res.Incomplete || !strings.Contains(res.Answer, "cannot be determined") || model.calls != 0 { t.Fatalf("%+v",res) }
}
func TestUnsupportedNameLookupFailsClosed(t *testing.T) {
	model := &noCallModel{}
	_,err:=(Agent{Model:model,Runner:ToolRunner{Graph:graph(),Limits:DefaultLimits()}}).Ask(context.Background(),"What subsidiaries does Acme Holdings Inc. have?")
	if err==nil || !strings.Contains(err.Error(),"does not support") {t.Fatalf("expected unsupported lookup: %v",err)}
}
type retryModel struct{ count int }
func (m *retryModel) Generate(_ context.Context, messages []Message, _ []ToolSpec)(Response,error){
	m.count++
	if m.count == 1 {return Response{Text:"I do not know."}, nil}
	if m.count == 2 {
		if !strings.Contains(messages[len(messages)-1].Text, "MUST call") { return Response{}, errors.New("missing retry prompt") }
		return Response{Calls:[]Call{{ID:"1",Name:"get_asset",Arguments:[]byte(`{"id":"a"}`)}}},nil
	}
	return Response{Text:"The database confirms an Organization a; no ownership inference made."},nil
}
func TestAgentRetriesUngroundedAnswerOnce(t *testing.T){
	model:=&retryModel{}
	res,err:=(Agent{Model:model,Runner:ToolRunner{Graph:graph(),Limits:DefaultLimits()}}).Ask(context.Background(),"Inspect asset a.")
	if err != nil || model.count!=3 || res.ToolCalls!=1 {t.Fatalf("got %+v err=%v calls=%d",res,err,model.count)}
}
