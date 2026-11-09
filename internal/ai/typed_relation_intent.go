// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "context"
 "errors"
 "fmt"
 "net/netip"
 "net/url"
 "regexp"
 "sort"
 "strings"
 "time"
)

// TypedRelationIntent compiles an unambiguous, user-named OAM relationship
// query into exact, catalog-validated hops. It is not a guess about ownership.
// More complex/ambiguous language is left to the semantic planner.
type TypedRelationIntent struct {
 Goal InvestigationGoal
 Hops []PlanHop
}

var typedRelationQuestion=regexp.MustCompile("(?i)^\\s*(?:which|what|list|show)(?:\\s+(?:all|the))?\\s+(.+?)\\s+(?:are\\s+)?(?:associated|connected|related|linked)\\s+(?:with|to)\\s+(.+?)\\s+(?:through|via|using)\\s+(.+?)\\s+(?:relationships|relations|edges)\\s*\\??\\s*$")
var typedSubject=regexp.MustCompile("^([A-Za-z][A-Za-z0-9]*):([a-zA-Z][a-zA-Z0-9_]+)=(.+)$")
var camelBoundary1=regexp.MustCompile("([a-z0-9])([A-Z])")
var camelBoundary2=regexp.MustCompile("([A-Z])([A-Z][a-z])")

func intentAssetAliases(kind string)[]string {
 words:=strings.ToLower(camelBoundary1.ReplaceAllString(camelBoundary2.ReplaceAllString(kind,"$1 $2"),"$1 $2"))
 variants:=[]string{strings.ToLower(kind),words}
 if kind=="IPAddress"{variants=append(variants,"ip","ips","ip address","ip addresses")}
 if kind=="FQDN"{variants=append(variants,"fqdn","fqdns","fully qualified domain name","fully qualified domain names")}
 if kind=="URL"{variants=append(variants,"url","urls")}
 if kind=="TLSCertificate"{variants=append(variants,"tls certificate","tls certificates")}
 if kind=="AutonomousSystem"{variants=append(variants,"asn","asns","autonomous system","autonomous systems")}
 for _,base:=range []string{strings.ToLower(kind),words}{
  if strings.HasSuffix(base,"y"){variants=append(variants,strings.TrimSuffix(base,"y")+"ies")}else{variants=append(variants,base+"s")}
 }
 return variants
}

func intentTargetType(raw string,selector []AssetSearchSchema,relations []RelationshipSchema)(string,bool){
 raw=strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(raw))," "))
 raw=strings.TrimSuffix(raw," assets")
 raw=strings.TrimSuffix(raw," asset")
 known:=map[string]bool{}
 for _,s:=range selector{known[s.Type]=true}
 for _,r:=range relations{known[r.SourceType]=true;known[r.DestinationType]=true}
 found:=""
 for typ:=range known{
  for _,alias:=range intentAssetAliases(typ){
   if raw!=alias{continue}
   if found!=""&&found!=typ{return "",false}
   found=typ
  }
 }
 return found,found!=""
}

func intentSubject(raw string,selectors []AssetSearchSchema)(PlanSubject,bool){
 raw=strings.TrimSpace(raw)
 if m:=typedSubject.FindStringSubmatch(raw);len(m)==4{
  value:=strings.TrimSpace(m[3])
  if len(value)>=2&&value[0]=='"'&&value[len(value)-1]=='"'{value=value[1:len(value)-1]}
  subject:=PlanSubject{Type:m[1],Field:m[2],Value:value}
  if err:=subject.AssetSelector().Validate(selectors);err==nil{return subject,true}
  return PlanSubject{},false
 }
 if strings.ContainsAny(raw," \t\n\r")||strings.Contains(raw,"@"){return PlanSubject{},false}
 // URL and IP parsers are exact; do not turn a partial URL into an FQDN.
 if strings.Contains(raw,"://"){
  parsed,err:=url.Parse(raw)
  if err!=nil||parsed.Host==""||parsed.User!=nil{return PlanSubject{},false}
  subject:=PlanSubject{Type:"URL",Field:"url",Value:raw}
  if subject.AssetSelector().Validate(selectors)==nil{return subject,true}
  return PlanSubject{},false
 }
 if ip,err:=netip.ParseAddr(raw);err==nil{
  subject:=PlanSubject{Type:"IPAddress",Field:"address",Value:ip.String()}
  if subject.AssetSelector().Validate(selectors)==nil{return subject,true}
  return PlanSubject{},false
 }
 if !hostnameInQuestion.MatchString(raw)||strings.Contains(raw,"..")||strings.HasPrefix(raw,".")||strings.HasSuffix(raw,"."){
  return PlanSubject{},false
 }
 if matches:=hostnameInQuestion.FindAllStringSubmatch(raw,-1);len(matches)!=1||matches[0][1]!=raw{return PlanSubject{},false}
 subject:=PlanSubject{Type:"FQDN",Field:"name",Value:strings.ToLower(raw)}
 if subject.AssetSelector().Validate(selectors)==nil{return subject,true}
 return PlanSubject{},false
}

// compileCatalogHops finds exactly one directed traversal route for the
// explicit labels and source/target types. Unordered labels may be permuted,
// but no intermediate relation is inferred, and competing paths fail closed.
func compileCatalogHops(root,target string,hint explicitRelationHint,relations []RelationshipSchema)([]PlanHop,bool){
 if len(hint.Labels)==0||len(hint.Labels)>maxPlanHops{return nil,false}
 type state struct{kind string;hops []PlanHop;used uint8}
 unique:=map[string][]PlanHop{}
 var visit func(state)
 visit=func(s state){
  if len(unique)>1{return}
  if len(s.hops)==len(hint.Labels){
   if s.kind!=target{return}
   var signature strings.Builder
   for _,hop:=range s.hops{signature.WriteString(hop.Direction);signature.WriteByte(0);signature.WriteString(hop.Label);signature.WriteByte(0);signature.WriteString(hop.RelationType);signature.WriteByte(0);signature.WriteString(hop.DestinationType);signature.WriteByte(0)}
   unique[signature.String()]=append([]PlanHop(nil),s.hops...)
   return
  }
  for i,label:=range hint.Labels{
   if s.used&(1<<uint(i))!=0{continue}
   if hint.Rule=="ordered"&&i!=len(s.hops){continue}
   for _,r:=range relations{
    if !strings.EqualFold(r.Label,label){continue}
    for _,choice:=range []struct{from,to,dir string}{{r.SourceType,r.DestinationType,"out"},{r.DestinationType,r.SourceType,"in"}}{
     if choice.from!=s.kind{continue}
     hop:=PlanHop{Direction:choice.dir,Label:r.Label,RelationType:r.RelationType,DestinationType:choice.to}
     visit(state{kind:choice.to,hops:append(append([]PlanHop(nil),s.hops...),hop),used:s.used|(1<<uint(i))})
    }
   }
  }
 }
 visit(state{kind:root})
 if len(unique)!=1{return nil,false}
 for _,hops:=range unique{return hops,true}
 return nil,false
}

func deterministicTypedRelationIntent(question string,catalog SchemaCatalog)(TypedRelationIntent,bool){
 var zero TypedRelationIntent
 selectors,ok:=catalog.(AssetSearchCatalog)
 if !ok{return zero,false}
 matches:=typedRelationQuestion.FindStringSubmatch(question)
 if len(matches)!=4{return zero,false}
 relations,fields:=catalog.Relations(),selectors.SearchFields()
 target,ok:=intentTargetType(matches[1],fields,relations)
 if !ok{return zero,false}
 subject,ok:=intentSubject(matches[2],fields)
 if !ok{return zero,false}
 hint,ok:=explicitRelationLabels(question,relations)
 if !ok||len(hint.Labels)>maxPlanHops{return zero,false}
 hops,ok:=compileCatalogHops(subject.Type,target,hint,relations)
 if !ok{return zero,false}
 plan:=TypedPlan{Subject:subject,Hops:hops}
 if err:=validatePlanWithSelectors(plan,relations,fields,DefaultLimits());err!=nil{return zero,false}
 required:=make([]GoalRelation,0,len(hops))
 current:=subject.Type
 for _,h:=range hops{
  for _,r:=range relations{
   if r.Label!=h.Label||r.RelationType!=h.RelationType{continue}
   if (h.Direction=="out"&&r.SourceType==current&&r.DestinationType==h.DestinationType)||
     (h.Direction=="in"&&r.DestinationType==current&&r.SourceType==h.DestinationType){
    required=append(required,GoalRelation{SourceType:r.SourceType,Label:r.Label,RelationType:r.RelationType,DestinationType:r.DestinationType})
    break
   }
  }
  current=h.DestinationType
 }
 if len(required)!=len(hops){return zero,false}
 goal:=InvestigationGoal{Subject:subject,TargetTypes:[]string{target},Direction:"both",
  Purpose:"connected",Relationships:required,PathRule:"ordered"}
 if err:=validateGoal(goal,relations,fields);err!=nil{return zero,false}
 return TypedRelationIntent{Goal:goal,Hops:hops},true
}

// searchTypedRelationIntent executes the compiled route with server-side
// direction+label bounds. This avoids wasting the global match budget on
// unrelated URLs, DNS, TLS and other OAM graph neighbors.
func searchTypedRelationIntent(ctx context.Context,graph Graph,limits Limits,root Asset,intent TypedRelationIntent,opts AdaptiveOptions)(GraphSearchResult,error){
 out:=GraphSearchResult{Root:root,Matches:[]PlanMatch{},Mode:"typed_relation_inventory"}
 if err:=limits.Validate();err!=nil{return out,err}
 bounded,ok:=graph.(BoundedGraph)
 if !ok{return out,errors.New("bounded graph reader required")}
 if root.Type!=intent.Goal.Subject.Type{return out,errors.New("resolved root type differs from intent subject")}
 if len(intent.Hops)<1||len(intent.Hops)>maxPlanHops{return out,errors.New("invalid typed intent hop count")}
 depth:=opts.MaxDepth
 if depth==0{depth=limits.MaxDepth}
 if depth<1||depth>limits.MaxDepth{return out,errors.New("invalid depth")}
 if depth<len(intent.Hops){out.Truncated=true;out.Reason="depth limit";out.VisitedNodes=1;return out,nil}
 maxMatches:=opts.MaxMatches
 if maxMatches==0{maxMatches=min(20,limits.MaxFind)}
 if maxMatches<1||maxMatches>limits.MaxFind{return out,errors.New("max matches exceeds policy")}
 maxExpansions:=opts.MaxExpansions
 if maxExpansions==0{maxExpansions=min(200,limits.MaxNodes)}
 if maxExpansions<1||maxExpansions>min(400,limits.MaxNodes*8){return out,errors.New("max expansions exceeds policy")}
 paths:=[]PlanMatch{{Nodes:[]Asset{root}}}
 seenNodes:=map[string]bool{root.ID:true}
 seenEdges:=map[string]bool{}
 seenMatches:=map[string]bool{}
 for index,hop:=range intent.Hops{
  nextPaths:=make([]PlanMatch,0)
  for _,path:=range paths{
   if err:=ctx.Err();err!=nil{return out,err}
   if out.ExpandedPaths>=maxExpansions{out.Truncated=true;out.Reason="path expansion limit";break}
   out.ExpandedPaths++
   last:=path.Nodes[len(path.Nodes)-1]
   edges,more,err:=bounded.EdgesLimited(ctx,last.ID,hop.Direction,hop.Label,time.Time{},limits.MaxPerNode)
   if err!=nil{return out,err}
   if len(edges)>limits.MaxPerNode{return out,errors.New("bounded graph exceeded per-node edge policy")}
   if more{out.Truncated=true;if out.Reason==""{out.Reason="per-node edge limit"}}
   sort.Slice(edges,func(i,j int)bool{return edges[i].ID<edges[j].ID})
   for _,edge:=range edges{
    if err:=ctx.Err();err!=nil{return out,err}
    if edge.Label!=hop.Label||edge.Type!=hop.RelationType{out.SchemaRejected++;continue}
    dest:=""
    if hop.Direction=="out"&&edge.FromID==last.ID{dest=edge.ToID}
    if hop.Direction=="in"&&edge.ToID==last.ID{dest=edge.FromID}
    if dest==""{out.SchemaRejected++;continue}
    cycle:=false
    for _,node:=range path.Nodes{if node.ID==dest{cycle=true;break}}
    if cycle{continue}
    if !seenEdges[edge.ID]{
     if len(seenEdges)>=limits.MaxEdges{out.Truncated=true;out.Reason="edge limit";break}
     seenEdges[edge.ID]=true
    }
    if !seenNodes[dest]&&len(seenNodes)>=limits.MaxNodes{out.Truncated=true;out.Reason="node limit";break}
    asset,err:=graph.GetAsset(ctx,dest)
    if err!=nil{return out,err}
    if asset.Type!=hop.DestinationType{out.SchemaRejected++;continue}
    seenNodes[dest]=true
    witness:=PlanMatch{
     Nodes:append(append([]Asset(nil),path.Nodes...),asset),
     Edges:append(append([]Relation(nil),path.Edges...),edge),
    }
    witness.PathID=WitnessPathID(witness)
    if index==len(intent.Hops)-1 {
     if seenMatches[asset.ID]{continue}
     seenMatches[asset.ID]=true
     out.Matches=append(out.Matches,witness)
     if len(out.Matches)>=maxMatches{out.Truncated=true;out.Reason="match limit";break}
    }else{
     nextPaths=append(nextPaths,witness)
    }
   }
   if out.Reason=="match limit"||out.Reason=="edge limit"||out.Reason=="node limit"{break}
  }
  if out.Reason=="match limit"||out.Reason=="edge limit"||out.Reason=="node limit"||out.Reason=="path expansion limit"{break}
  paths=nextPaths
 }
 out.VisitedNodes=len(seenNodes)
 out.VisitedEdges=len(seenEdges)
 out.Exhausted=!out.Truncated
 sort.Slice(out.Matches,func(i,j int)bool{
  a,b:=out.Matches[i],out.Matches[j]
  x,y:=a.Nodes[len(a.Nodes)-1],b.Nodes[len(b.Nodes)-1]
  if x.Key==y.Key{return a.PathID<b.PathID}
  return x.Key<y.Key
 })
 return out,nil
}

func typedRelationAnswer(root Asset,intent TypedRelationIntent,paths []PlanMatch,truncated bool,reason string)string{
 target:=""
 if len(intent.Goal.TargetTypes)>0{target=intent.Goal.TargetTypes[0]}
 names:=make([]string,0,len(paths))
 for _,path:=range paths{if len(path.Nodes)>0{names=append(names,path.Nodes[len(path.Nodes)-1].Key)}}
 sort.Strings(names)
 labels:=make([]string,0,len(intent.Hops))
 for _,hop:=range intent.Hops{labels=append(labels,hop.Direction+":"+hop.Label+"/"+hop.RelationType)}
 answer:=fmt.Sprintf("Found %d %s asset(s) connected to %s through stored OAM relationship path [%s]:",
  len(names),target,root.Key,strings.Join(labels," -> "))
 if len(names)>0{answer+="\n"+strings.Join(names,"\n")}
 answer+="\nThese are stored graph associations, not independently verified ownership or current reachability."
 if truncated{answer+=" Results are partial (search truncated: "+reason+"); additional matches may exist."}
 return answer
}
