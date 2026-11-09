// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "context"
 "errors"
 "fmt"
 "regexp"
 "sort"
 "strings"
 "time"
)

// Only unambiguous FQDN inventory questions qualify for this fast path.
// "Associated" in this narrow mode means descending stored OAM "node"
// edges, not DNS-record association, organization attribution or validation.
// Ambiguous questions still fall through to the model planner.
var fqdnInventoryQuestion=regexp.MustCompile(`(?i)^\s*(?:(?:which|what|list|show)(?:\s+(?:all|the))?\s+(?:fqdn|fqdns|fully qualified domain name|fully qualified domain names|hostname|hostnames|dns names?|subdomain|subdomains|subdomain names?)(?:\s+assets)?(?:\s+(?:are|were))?(?:\s+(?:associated|connected|related)\s+with|\s+(?:under|beneath|within|for|of))|(?:list|show)\s+(?:all\s+)?(?:subdomains|subdomain names|hostnames)\s+(?:of|under|for))\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:\s*\?)?\s*$`)

func deterministicFQDNInventoryGoal(question string,catalog SchemaCatalog)(InvestigationGoal,bool){
 var zero InvestigationGoal
 m:=fqdnInventoryQuestion.FindStringSubmatch(question)
 if len(m)!=2{return zero,false}
 host:=strings.ToLower(m[1])
 if strings.Contains(host,"..")||strings.Contains(host,".-")||strings.Contains(host,"-.")||strings.HasSuffix(host,"."){return zero,false}
 selector,ok:=catalog.(AssetSearchCatalog)
 if !ok{return zero,false}
 foundField,foundNode:=false,false
 for _,s:=range selector.SearchFields(){
  if s.Type!="FQDN"{continue}
  for _,field:=range s.Fields{if field=="name"{foundField=true}}
 }
 for _,r:=range catalog.Relations(){
  if r.SourceType=="FQDN"&&r.DestinationType=="FQDN"&&r.Label=="node"&&r.RelationType=="SimpleRelation"{foundNode=true}
 }
 if !foundField||!foundNode{return zero,false}
 goal:=InvestigationGoal{
  Subject:PlanSubject{Type:"FQDN",Field:"name",Value:host},
  TargetTypes:[]string{"FQDN"},Direction:"out",Purpose:"connected",
  Relationships:[]GoalRelation{{SourceType:"FQDN",DestinationType:"FQDN",Label:"node",RelationType:"SimpleRelation"}},
  PathRule:"all",
 }
 if err:=validateGoal(goal,catalog.Relations(),selector.SearchFields());err!=nil{return zero,false}
 return goal,true
}

// searchFQDNInventory is deliberately bounded and schema-grounded.
// Traversing only outgoing FQDN --node/SimpleRelation--> FQDN avoids
// spending match limits on unrelated DNS, URLs, IPs and organizations.
// A suffix check ensures a malformed stored relation cannot pull an
// unrelated FQDN into the requested scope.
func searchFQDNInventory(ctx context.Context,graph Graph,limits Limits,root Asset,opts AdaptiveOptions)(GraphSearchResult,error){
 out:=GraphSearchResult{Root:root,Matches:[]PlanMatch{},Mode:"fqdn_inventory"}
 if err:=limits.Validate();err!=nil{return out,err}
 if root.Type!="FQDN"{return out,errors.New("FQDN inventory requires FQDN root")}
 bounded,ok:=graph.(BoundedGraph)
 if !ok{return out,errors.New("bounded graph reader required")}
 depth,maxMatches,maxExpansions:=opts.MaxDepth,opts.MaxMatches,opts.MaxExpansions
 if depth==0{depth=limits.MaxDepth}
 if maxMatches==0{maxMatches=min(20,limits.MaxFind,limits.MaxNodes-1)}
 if maxExpansions==0{maxExpansions=min(200,limits.MaxNodes)}
 if depth<1||depth>limits.MaxDepth{return out,errors.New("depth exceeds policy")}
 if maxMatches<1||maxMatches>limits.MaxFind||maxMatches>=limits.MaxNodes{return out,errors.New("max matches exceeds inventory policy")}
 if maxExpansions<1||maxExpansions>min(400,limits.MaxNodes*8){return out,errors.New("max expansions exceeds policy")}
 type queued struct{asset Asset;path PlanMatch}
 initial:=PlanMatch{Nodes:[]Asset{root},Edges:[]Relation{}}
 initial.PathID=WitnessPathID(initial)
 pending:=[]queued{{asset:root,path:initial}}
 seen:=map[string]bool{root.ID:true}
 seenEdges:=map[string]bool{}
 rootName:=strings.ToLower(strings.TrimSuffix(root.Key,"."))
 for len(pending)>0{
  if err:=ctx.Err();err!=nil{return out,err}
  if out.ExpandedPaths>=maxExpansions{
   out.Truncated=true;out.Reason="path expansion limit";break
  }
  current:=pending[0];pending=pending[1:]
  if len(current.path.Edges)>=depth{continue}
  out.ExpandedPaths++
  edges,more,err:=bounded.EdgesLimited(ctx,current.asset.ID,"out","node",time.Time{},limits.MaxPerNode)
  if err!=nil{return out,err}
  if len(edges)>limits.MaxPerNode{return out,errors.New("bounded graph returned too many node edges")}
  if more{out.Truncated=true;if out.Reason==""{out.Reason="per-node edge limit"}}
  sort.Slice(edges,func(i,j int)bool{return edges[i].ID<edges[j].ID})
  for _,edge:=range edges{
   if err:=ctx.Err();err!=nil{return out,err}
   if edge.FromID!=current.asset.ID||edge.ToID==""||edge.Type!="SimpleRelation"||edge.Label!="node"{
    out.SchemaRejected++;continue
   }
   if !seenEdges[edge.ID] {
    if len(seenEdges)>=limits.MaxEdges{out.Truncated=true;out.Reason="edge limit";break}
    seenEdges[edge.ID]=true
   }
   if seen[edge.ToID]{continue}
   if len(seen)>=limits.MaxNodes{out.Truncated=true;out.Reason="node limit";break}
   next,err:=graph.GetAsset(ctx,edge.ToID)
   if err!=nil{return out,err}
   nextName:=strings.ToLower(strings.TrimSuffix(next.Key,"."))
   if next.Type!="FQDN"||!strings.HasSuffix(nextName,"."+rootName){
    out.SchemaRejected++;continue
   }
   seen[next.ID]=true
   path:=PlanMatch{
    Nodes:append(append([]Asset(nil),current.path.Nodes...),next),
    Edges:append(append([]Relation(nil),current.path.Edges...),edge),
   }
   path.PathID=WitnessPathID(path)
   out.Matches=append(out.Matches,path)
   pending=append(pending,queued{asset:next,path:path})
   if len(out.Matches)>=maxMatches{
    out.Truncated=true;out.Reason="match limit";break
   }
  }
  if out.Reason=="match limit"||out.Reason=="node limit"||out.Reason=="edge limit"{break}
 }
 out.VisitedNodes=len(seen)
 out.VisitedEdges=len(seenEdges)
 if out.SchemaRejected>0&&!out.Truncated{out.Truncated=true;out.Reason="stored edge absent from FQDN node taxonomy/scope"}
 out.Exhausted=!out.Truncated
 // Make names deterministic independent of database edge identifier order.
 sort.Slice(out.Matches,func(i,j int)bool{
  a:=out.Matches[i].Nodes[len(out.Matches[i].Nodes)-1].Key
  b:=out.Matches[j].Nodes[len(out.Matches[j].Nodes)-1].Key
  if a==b{return out.Matches[i].PathID<out.Matches[j].PathID}
  return a<b
 })
 return out,nil
}

// The apex is an FQDN asset, but is not itself a subdomain of the apex.
// Keep the older generic FQDN-inventory contract and specialize only when
// the question explicitly requests subdomains.
func fqdnInventoryAnswer(root Asset,paths []PlanMatch,truncated bool,reason string)string{
 return fqdnInventoryAnswerScoped(root,paths,truncated,reason,false)
}

func fqdnInventoryAnswerScoped(root Asset,paths []PlanMatch,truncated bool,reason string,subdomainsOnly bool)string{
 names:=make([]string,0,len(paths)+1)
 if !subdomainsOnly{names=append(names,root.Key)}
 seen:=map[string]bool{root.ID:true}
 for _,path:=range paths{
  if len(path.Nodes)==0{continue}
  last:=path.Nodes[len(path.Nodes)-1]
  if seen[last.ID]{continue}
  seen[last.ID]=true
  names=append(names,last.Key)
 }
 sort.Strings(names)
 description:="FQDN asset(s)"
 if subdomainsOnly{description="subdomain FQDN asset(s)"}
 answer:=fmt.Sprintf("Found %d %s in the stored OAM node hierarchy for %s:\n%s",len(names),description,root.Key,strings.Join(names,"\n"))
 answer+="\nThese are stored FQDN asset associations, not proof of current DNS resolution or ownership."
 if truncated{answer+=" Results are partial (search truncated: "+reason+"); additional names may exist."}
 return answer
}

var subdomainInventoryLanguage=regexp.MustCompile(`(?i)\bsubdomains?\b`)

func isSubdomainInventoryQuestion(question string)bool{
 return subdomainInventoryLanguage.MatchString(question)
}
