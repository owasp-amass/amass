// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "reflect"
 "strings"
 "testing"
)

func TestRelationAliasGrounding(t *testing.T){
 cat:=[]RelationshipSchema{
  {SourceType:"FQDN",Label:"dns_record",RelationType:"BasicDNSRelation",DestinationType:"IPAddress"},
  {SourceType:"FQDN",Label:"node",RelationType:"SimpleRelation",DestinationType:"FQDN"},
  {SourceType:"URL",Label:"domain",RelationType:"SimpleRelation",DestinationType:"FQDN"},
  {SourceType:"Organization",Label:"website",RelationType:"SimpleRelation",DestinationType:"URL"},
  {SourceType:"Organization",Label:"registration",RelationType:"SimpleRelation",DestinationType:"DomainRecord"},
 }
 cases:=[]struct{question string;labels []string}{
  {"Which IP addresses are connected to test.example via DNS resolution relationships?",[]string{"dns_record"}},
  {"Which companies are connected to test.example via domain and official website relationships?",[]string{"domain","website"}},
  {"Which hostnames are connected to test.example using subdomain hierarchy edges?",[]string{"node"}},
  {"Which registration records are connected to test.example via domain registration relations?",[]string{"registration"}},
  {"Which IP addresses are connected to test.example via dns_record relationships?",[]string{"dns_record"}},
 }
 for _,tc:=range cases{
  hint,ok:=explicitRelationLabels(tc.question,cat)
  if !ok||!reflect.DeepEqual(hint.Labels,tc.labels){
   t.Errorf("%q: labels=%v ok=%v want=%v",tc.question,hint.Labels,ok,tc.labels)
  }
 }
}

func TestRelationAliasNeverInventsUnregisteredEdges(t *testing.T){
 cat:=[]RelationshipSchema{
  {SourceType:"URL",Label:"domain",RelationType:"SimpleRelation",DestinationType:"FQDN"},
 }
 if got:=schemaRelationAliasCandidates("dns resolution",cat);len(got)!=0{
  t.Fatalf("alias invented dns_record relationship: %v",got)
 }
 if _,ok:=explicitRelationLabels("Which IPs are connected to test.example via dns resolution relationships?",cat);ok{
  t.Fatal("unregistered DNS relationship was accepted")
 }
}

func TestRelationAliasAmbiguityFailsClosed(t *testing.T){
 cat:=[]RelationshipSchema{
  {SourceType:"Organization",Label:"website",RelationType:"SimpleRelation",DestinationType:"URL"},
  {SourceType:"FQDN",Label:"official_website",RelationType:"SimpleRelation",DestinationType:"URL"},
 }
 q:="Which URLs are connected to test.example via official website relationships?"
 if _,ok:=explicitRelationLabels(q,cat);ok{
  t.Fatal("same alias mapped to different labels without disambiguation")
 }
}

func TestRelationshipAndFieldVocabularyScopesToCatalog(t *testing.T){
 cat:=[]RelationshipSchema{
  {SourceType:"FQDN",Label:"dns_record",RelationType:"BasicDNSRelation",DestinationType:"IPAddress"},
 }
 selectors:=[]AssetSearchSchema{{Type:"FQDN",Fields:[]string{"name","unique_id"}}}
 relPrompt:=compactRelationshipVocabulary(cat)
 if !strings.Contains(relPrompt,"dns_record:")||strings.Contains(relPrompt,"subsidiary:"){
  t.Fatalf("wrong relationship prompt scope: %q",relPrompt)
 }
 fieldPrompt:=compactSearchVocabulary(selectors)
 if !strings.Contains(fieldPrompt,"unique_id:")||strings.Contains(fieldPrompt,"registration_id:"){
  t.Fatalf("wrong indexed-field prompt scope: %q",fieldPrompt)
 }
}

func TestRelationAliasCatalogWideDynamicNaming(t *testing.T){
 cat:=[]RelationshipSchema{
  {SourceType:"Account",Label:"account_linked_to",RelationType:"SimpleRelation",DestinationType:"Organization"},
 }
 for _,name:=range []string{"account_linked_to","account linked to","account-linked-to"}{
  got:=schemaRelationAliasCandidates(name,cat)
  if !reflect.DeepEqual(got,[]string{"account_linked_to"}){
   t.Errorf("dynamic alias %q not resolved, got %+v",name,got)
  }
 }
}

func TestRegisteredRelationLabelsGeneratePluralNouns(t *testing.T){
 cat:=[]RelationshipSchema{
  {SourceType:"FQDN",Label:"custom_record",RelationType:"SimpleRelation",DestinationType:"URL"},
  {SourceType:"FQDN",Label:"service_category",RelationType:"SimpleRelation",DestinationType:"Service"},
 }
 for phrase,want:=range map[string]string{
  "custom record":"custom_record",
  "custom records":"custom_record",
  "service category":"service_category",
  "service categories":"service_category",
 }{
  got:=schemaRelationAliasCandidates(phrase,cat)
  if !reflect.DeepEqual(got,[]string{want}){
   t.Errorf("registered %q should match %s: %+v",phrase,want,got)
  }
 }
}
