// SPDX-License-Identifier: Apache-2.0
package ai

import (
 "context"
 "sort"
)

// AnswerGroup keeps the preferred explanation separate from all alternative
// witnessed routes for the same destination. Source-tag coverage is a
// preference for presentation, never a probability of correctness.
type AnswerGroup struct {
 AssetID string `json:"asset_id"`
 AssetType string `json:"asset_type"`
 Display string `json:"display"`
 PreferredPathID string `json:"preferred_path_id"`
 AlternativePathIDs []string `json:"alternative_path_ids"`
 DirectToGoal bool `json:"direct_to_goal"`
}

// selectAnswerPaths retains the entire searched graph and evidence dossier,
// but reduces the model's decision space to one representative path per
// destination. When an explicit relationship goal is fully satisfied at an
// earlier target node, paths continuing to other targets are related context
// rather than the closest answer to that goal. No model/heuristic can erase
// those paths from search.matches or evidence_dossier.
func(a Agent) selectAnswerPaths(ctx context.Context,question string,goal InvestigationGoal,paths []PlanMatch,dossier *EvidenceDossier)([]PlanMatch,[]AnswerGroup,bool,error){
 groups:=map[string][]PlanMatch{}
 typeInfo:=map[string]Asset{}
 for _,path:=range paths{
  if len(path.Nodes)==0{continue}
  last:=path.Nodes[len(path.Nodes)-1]
  groups[last.ID]=append(groups[last.ID],path)
  typeInfo[last.ID]=last
 }
 byEvidence:=map[string]PathEvidence{}
 if dossier!=nil{for _,p:=range dossier.Paths{byEvidence[p.PathID]=p}}
 ids:=make([]string,0,len(groups))
 for id:=range groups{ids=append(ids,id)}
 sort.Strings(ids)
 var summaries []AnswerGroup
 var representatives []PlanMatch
 direct:=map[string]bool{}
 for _,id:=range ids{
  options:=groups[id]
  candidates:=make([]adaptiveCandidate,0,len(options))
  byPath:=map[string]PlanMatch{}
  for _,p:=range options{
   pid:=p.PathID
   if pid==""{pid=WitnessPathID(p);p.PathID=pid}
   byPath[pid]=p
   cand:=adaptiveCandidate{AssetID:id,PathID:pid,Depth:len(p.Edges)}
   if evidence,ok:=byEvidence[pid];ok{
    cand.Coverage,_=pathSourceCoverage(evidence)
   }else{
    cand.Coverage=PathSourceCoverage{TotalEdges:len(p.Edges),UnassessedEdges:len(p.Edges)}
   }
   candidates=append(candidates,cand)
  }
  rankComparableAlternates(candidates)
  best:=byPath[candidates[0].PathID]
  isDirect:=true
  if goal.Purpose=="connected"&&len(goal.Relationships)>0 {
   for _,p:=range options{
    for i:=1;i<len(p.Nodes)-1;i++{
     prior:=p.Nodes[i]
     if prior.Type!=typeInfo[id].Type{continue}
     prefix:=PlanMatch{Nodes:p.Nodes[:i+1],Edges:p.Edges[:i]}
     if pathSatisfiesGoal(prefix,goal.Relationships,goal.PathRule){
      // All witness routes to this destination that reach a
      // completed target earlier are contextual rather than direct.
      if p.PathID==best.PathID{isDirect=false}
      break
     }
    }
   }
  }
  summary:=AnswerGroup{
   AssetID:id,AssetType:typeInfo[id].Type,Display:humanAsset(typeInfo[id]),
   PreferredPathID:best.PathID,AlternativePathIDs:[]string{},DirectToGoal:isDirect,
  }
  for _,c:=range candidates[1:]{summary.AlternativePathIDs=append(summary.AlternativePathIDs,c.PathID)}
  summaries=append(summaries,summary)
  direct[id]=isDirect
  representatives=append(representatives,best)
 }
 // Context is retained in summaries and full evidence; prefer minimum
 // semantically completed routes when at least one exists.
 var primary []PlanMatch
 for _,p:=range representatives{
  if goal.Purpose=="connected"&&len(goal.Relationships)>0 && !direct[p.Nodes[len(p.Nodes)-1].ID]{continue}
  primary=append(primary,p)
 }
 if len(primary)==0{primary=representatives}
 if len(primary)<=1{return primary,summaries,true,nil}
 selected,err:=a.chooseAdaptivePathsWithEvidence(ctx,question,goal,primary,dossier)
 return selected,summaries,false,err
}
