// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "fmt"
 "regexp"
 "sort"
 "strings"
)

// namedRelationshipPhrase requires the user to explicitly name OAM
// relationship labels in a "through/via/using ... relationships" clause.
// Domain names, organization names, and bare words elsewhere in a question
// are not promoted into graph constraints.
var namedRelationshipPhrase=regexp.MustCompile(`(?is)\b(?:through|via|using|along)\b(.{1,140}?)\b(?:relationships|relations|edges)\b`)
var explicitlyOrderedRelations=regexp.MustCompile(`(?i)\b(?:then|followed by|in that order|in this order|in sequence)\b`)

type explicitRelationHint struct {
 Labels []string
 Rule string
 RawPhrase string
}

// explicitRelationLabels only discovers exact catalog label words from an
// explicit relationship phrase. It does not infer unseen edges or ownership.
func explicitRelationLabels(question string,catalog []RelationshipSchema)(explicitRelationHint,bool){
 var hint explicitRelationHint
 matches:=namedRelationshipPhrase.FindAllStringSubmatch(question,-1)
 if len(matches)!=1{return hint,false}
 phrase:=strings.ToLower(matches[0][1])
 labels:=map[string]int{}
 for _,r:=range catalog{
  label:=strings.ToLower(r.Label)
  if label==""{continue}
  // An exact label word, not a substring of an asset name or another label.
  pattern:=regexp.MustCompile(`(^|[^a-z0-9_])`+regexp.QuoteMeta(label)+`([^a-z0-9_]|$)`)
  if loc:=pattern.FindStringIndex(phrase);loc!=nil{
   if previous,exists:=labels[label];!exists||loc[0]<previous{labels[label]=loc[0]}
  }
 }
 if len(labels)==0||len(labels)>4{return hint,false}
 hint.Labels=make([]string,0,len(labels))
 for label:=range labels{hint.Labels=append(hint.Labels,label)}
 sort.Slice(hint.Labels,func(i,j int)bool{
  if labels[hint.Labels[i]]==labels[hint.Labels[j]]{return hint.Labels[i]<hint.Labels[j]}
  return labels[hint.Labels[i]]<labels[hint.Labels[j]]
 })
 hint.Rule="all"
 if explicitlyOrderedRelations.MatchString(question){hint.Rule="ordered"}
 hint.RawPhrase=strings.TrimSpace(matches[0][1])
 return hint,true
}

// groundedRelationshipGoal derives the shortest, exact, schema-valid
// transition sequence for explicit relation labels between the model's
// validated root and *single* requested target type. It deliberately
// supports traversing a stored edge in either direction, as guided graph
// exploration does. No database relation is invented or assumed to exist.
//
// Fail closed when more than one distinct taxonomy sequence fits the same
// root/target/labels; the model must disambiguate the semantic goal.
func groundedRelationshipGoal(hint explicitRelationHint,rootType,targetType string,catalog []RelationshipSchema)([]GoalRelation,bool){
 if rootType==""||targetType==""||len(hint.Labels)==0{return nil,false}
 type pathState struct{kind string;steps []GoalRelation;seen uint8}
 initial:=pathState{kind:rootType}
 var found [][]GoalRelation
 distinct:=map[string]bool{}
 var walk func(pathState)
 walk=func(st pathState){
  if len(found)>1{return}
  if len(st.steps)==len(hint.Labels){
   if st.kind!=targetType{return}
   var key strings.Builder
   for _,r:=range st.steps{
    key.WriteString(relationKey(r.SourceType,r.Label,r.RelationType,r.DestinationType))
    key.WriteByte(0)
   }
   if !distinct[key.String()]{
    distinct[key.String()]=true
    found=append(found,append([]GoalRelation(nil),st.steps...))
   }
   return
  }
  for i,label:=range hint.Labels{
   if st.seen&(1<<uint(i))!=0{continue}
   if hint.Rule=="ordered"&&i!=len(st.steps){continue}
   for _,r:=range catalog{
    if !strings.EqualFold(r.Label,label){continue}
    next:=""
    switch st.kind{
    case r.SourceType:next=r.DestinationType
    case r.DestinationType:next=r.SourceType
    default:continue
    }
    step:=GoalRelation{SourceType:r.SourceType,Label:r.Label,RelationType:r.RelationType,DestinationType:r.DestinationType}
    nextSteps:=append(append([]GoalRelation(nil),st.steps...),step)
    walk(pathState{kind:next,steps:nextSteps,seen:st.seen|(1<<uint(i))})
   }
  }
 }
 walk(initial)
 if len(found)!=1{return nil,false}
 return found[0],true
}

// applyExplicitRelationGrounding changes ONLY relationship constraints.
// It is called after the model's subject, targets, direction and purpose
// have been validated independently. It never changes the user-selected
// asset identifier or destination types and does not fabricate OAM edges.
func applyExplicitRelationGrounding(goal InvestigationGoal,hint explicitRelationHint,catalog []RelationshipSchema)(InvestigationGoal,bool){
 if len(goal.TargetTypes)!=1{return goal,false}
 rels,ok:=groundedRelationshipGoal(hint,goal.Subject.Type,goal.TargetTypes[0],catalog)
 if !ok{return goal,false}
 goal.Relationships=rels
 goal.PathRule=hint.Rule
 return goal,true
}

// compactGroundingHint presents a tiny verified schema route near the start
// of the LLM prompt, rather than expecting a small local model to recover
// exact transitions from a very long complete OAM catalog.
func compactGroundingHint(hint explicitRelationHint,rels []GoalRelation)string{
 if len(rels)==0{return ""}
 var lines []string
 for i,r:=range rels{
  lines=append(lines,fmt.Sprintf("%d. %s --%s (%s)--> %s",i+1,r.SourceType,r.Label,r.RelationType,r.DestinationType))
 }
 return "The user EXPLICITLY named OAM relationship labels: "+strings.Join(hint.Labels,", ")+
  ". Use these labels as relationship constraints, NOT guessed WHOIS/registration edges. "+
  "For this root and requested destination, the taxonomy supports these exact stored-direction transitions (the query may traverse them backwards):\n"+
  strings.Join(lines,"\n")+"\nUse path_rule "+hint.Rule+".\n"
}
