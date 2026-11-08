// SPDX-License-Identifier: Apache-2.0
package cli

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "sort"
 "strings"

 "github.com/owasp-amass/amass/v5/internal/ai"
)

type graphSearchOptions struct {
 SubjectType string
 SubjectField string
 SubjectValue string
 SubjectID string
 TargetTypes string
 Direction string
 MaxDepth int
 MaxMatches int
 Since string
 Format string
}

type graphSearchResponse struct {
 Status string `json:"status"`
 Resolution *ai.AssetResolution `json:"asset_resolution,omitempty"`
 Search *ai.GraphSearchResult `json:"search,omitempty"`
 Collection *ai.CollectionPlan `json:"collection,omitempty"`
}

// graphSearch is a model-free path inspector. Its output is a useful
// regression oracle for an AI plan: returned paths contain only stored edges.
func graphSearch(ctx context.Context, runner ai.ToolRunner, opt graphSearchOptions, out io.Writer) error {
 if opt.Format=="" {opt.Format="json"}
 if opt.Format!="json" && opt.Format!="text" && opt.Format!="mermaid" {
  return errors.New("-format must be json, text, or mermaid")
 }
 if opt.SubjectID=="" && (opt.SubjectType=="" || opt.SubjectField=="" || opt.SubjectValue=="") {
  return errors.New("provide -subject-id, or all of -subject-type, -subject-field, and -subject-value")
 }
 if opt.SubjectID!="" && (opt.SubjectField!="" || opt.SubjectValue!="") {
  return errors.New("-subject-id cannot be combined with -subject-field or -subject-value")
 }
 id:=opt.SubjectID
 response:=graphSearchResponse{Status:"unresolved"}
 if id=="" {
  args,err:=json.Marshal(struct {
   ai.AssetSelector
   Limit int `json:"limit"`
  }{AssetSelector:ai.AssetSelector{Type:opt.SubjectType,Field:opt.SubjectField,Value:opt.SubjectValue},Limit:10})
  if err!=nil {return err}
  raw,err:=runner.Run(ctx,"resolve_asset",args)
  if err!=nil {return fmt.Errorf("resolve subject: %w",err)}
  var resolution ai.AssetResolution
  if err:=json.Unmarshal(raw,&resolution);err!=nil{return err}
  response.Resolution=&resolution
  if resolution.Status!="matched" || len(resolution.Candidates)!=1 {
   response.Status=resolution.Status
   if resolution.Status=="not_found" {
    plan:=ai.PlanCollection(ai.AssetSelector{Type:opt.SubjectType,Field:opt.SubjectField,Value:opt.SubjectValue})
    response.Collection=&plan
   }
   return writeGraphSearchResponse(out,opt.Format,response)
  }
  id=resolution.Candidates[0].Asset.ID
 }
 var targets []string
 if strings.TrimSpace(opt.TargetTypes)!="" {
  unique:=map[string]bool{}
  for _,t:=range strings.Split(opt.TargetTypes,",") {
   t=strings.TrimSpace(t)
   if t=="" {return errors.New("-target-types contains an empty type")}
   if !unique[t] {targets=append(targets,t);unique[t]=true}
  }
 }
 result,err:=ai.SearchGraph(ctx,runner.Graph,runner.Catalog,runner.Limits,ai.GraphSearchRequest{
  StartID:id,TargetTypes:targets,Direction:opt.Direction,MaxDepth:opt.MaxDepth,MaxMatches:opt.MaxMatches,Since:opt.Since,
 })
 if err!=nil {return err}
 if opt.SubjectType!="" && result.Root.Type!=opt.SubjectType {
  return fmt.Errorf("asset %q is %s, not asserted type %s",id,result.Root.Type,opt.SubjectType)
 }
 response.Status="matched"
 response.Search=&result
 return writeGraphSearchResponse(out,opt.Format,response)
}

func writeGraphSearchResponse(out io.Writer, format string, response graphSearchResponse) error {
 switch format {
 case "json":
  enc:=json.NewEncoder(out)
  enc.SetIndent("","  ")
  return enc.Encode(response)
 case "text":
  if response.Search==nil {
   _,err:=fmt.Fprintf(out,"Subject resolution: %s\n",response.Status)
   if err!=nil {return err}
   if response.Collection!=nil {_,err=fmt.Fprintf(out,"Collection: %s (%s); approval required: %t\n",response.Collection.Status,response.Collection.ID,response.Collection.RequiresApproval)}
   return err
  }
  r:=response.Search
  if _,err:=fmt.Fprintf(out,"Root: %s [%s] (asset %s)\nPaths: %d, visited nodes: %d, visited edges: %d, bounded complete: %t, truncated: %t\n",r.Root.Key,r.Root.Type,r.Root.ID,len(r.Matches),r.VisitedNodes,r.VisitedEdges,r.Exhausted,r.Truncated);err!=nil{return err}
  if r.Reason!="" {if _,err:=fmt.Fprintf(out,"Coverage limitation: %s\n",r.Reason);err!=nil{return err}}
  for i,path:=range r.Matches {
   if _,err:=fmt.Fprintf(out,"%d. depth=%d: ",i+1,len(path.Edges));err!=nil{return err}
   for j,node:=range path.Nodes {
    if j>0 {
     edge:=path.Edges[j-1]
     if path.Nodes[j-1].ID==edge.FromID {
      if _,err:=fmt.Fprintf(out," --%s [%s]--> ",edge.Label,edge.ID);err!=nil{return err}
     } else {
      if _,err:=fmt.Fprintf(out," <--%s [%s]-- ",edge.Label,edge.ID);err!=nil{return err}
     }
    }
    if _,err:=fmt.Fprintf(out,"%s (%s #%s)",node.Key,node.Type,node.ID);err!=nil{return err}
   }
   if _,err:=fmt.Fprintln(out);err!=nil{return err}
  }
  return nil
 case "mermaid":
  if response.Search==nil {return fmt.Errorf("cannot render %s result as Mermaid",response.Status)}
  nodes:=map[string]ai.Asset{response.Search.Root.ID:response.Search.Root}
  edges:=map[string]ai.Relation{}
  for _,p:=range response.Search.Matches {
   for _,n:=range p.Nodes {nodes[n.ID]=n}
   for _,e:=range p.Edges {edges[e.ID]=e}
  }
  nodeIDs:=make([]string,0,len(nodes))
  edgeIDs:=make([]string,0,len(edges))
  for id:=range nodes {nodeIDs=append(nodeIDs,id)}
  for id:=range edges {edgeIDs=append(edgeIDs,id)}
  sort.Strings(nodeIDs)
  sort.Strings(edgeIDs)
  walk:=ai.WalkResult{Truncated:response.Search.Truncated}
  for _,id:=range nodeIDs {walk.Nodes=append(walk.Nodes,nodes[id])}
  for _,id:=range edgeIDs {walk.Edges=append(walk.Edges,edges[id])}
  _,err:=fmt.Fprint(out,ai.Mermaid(walk))
  return err
 default:
  return errors.New("invalid search output format")
 }
}
