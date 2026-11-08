// SPDX-License-Identifier: Apache-2.0
package ai

import (
    "context"
    "errors"
    "fmt"
    "sort"
)

// GraphSearchRequest asks for witnessed paths through stored OAM relationships.
// Target types can include any registered OAM type. Different matches may be
// reached at different depths. This initial search retains one shortest path
// per distinct destination asset; alternate paths are future work.
type GraphSearchRequest struct {
    StartID string `json:"start_id"`
    TargetTypes []string `json:"target_types,omitempty"`
    Direction string `json:"direction,omitempty"`
    MaxDepth int `json:"max_depth,omitempty"`
    MaxMatches int `json:"max_matches,omitempty"`
    Since string `json:"since,omitempty"`
}

// Exhausted means the bounded search completed within MaxDepth, NOT that all
// relationships in the full Asset Database have been enumerated.
type GraphSearchResult struct {
    Root Asset `json:"root"`
    Matches []PlanMatch `json:"matches"`
    VisitedNodes int `json:"visited_nodes"`
    VisitedEdges int `json:"visited_edges"`
    SchemaRejected int `json:"schema_rejected"`
    Exhausted bool `json:"exhausted"`
    Truncated bool `json:"truncated"`
    Reason string `json:"reason,omitempty"`
    Mode string `json:"mode,omitempty"`
    ExpandedPaths int `json:"expanded_paths,omitempty"`
    AlternativeMatches int `json:"alternative_matches,omitempty"`
    AlternativePathsSkipped int `json:"alternative_paths_skipped,omitempty"`
}
type graphSearchStep struct {
    asset Asset
    path PlanMatch
    depth int
}

// SearchGraph performs a bounded, breadth-first, type-agnostic graph search.
// Edge queries are limited inside asset-db; every accepted transition is
// checked against the authoritative OAM catalog. Paths represent stored edges,
// never ownership claims or new AI-inferred relationships.
func SearchGraph(ctx context.Context, graph Graph, catalog SchemaCatalog, limits Limits, req GraphSearchRequest) (GraphSearchResult, error) {
    out := GraphSearchResult{Matches: []PlanMatch{}}
    if err:=limits.Validate(); err!=nil {return out,err}
    if graph==nil || catalog==nil {return out,errors.New("graph and OAM schema catalog are required")}
    bounded,ok:=graph.(BoundedGraph)
    if !ok {return out,errors.New("graph repository lacks bounded edge queries")}
    if req.StartID=="" {return out,errors.New("start_id required")}
    if req.Direction=="" {req.Direction="both"}
    if req.Direction!="both" && req.Direction!="in" && req.Direction!="out" {return out,errors.New("direction must be in, out, or both")}
    if req.MaxDepth==0 {
        if len(req.TargetTypes)==0 {req.MaxDepth=1} else {req.MaxDepth=limits.MaxDepth}
    }
    if req.MaxDepth<1 || req.MaxDepth>limits.MaxDepth {return out,errors.New("max_depth exceeds policy")}
    if req.MaxMatches==0 {req.MaxMatches=min(20,limits.MaxFind,limits.MaxNodes)}
    if req.MaxMatches<1 || req.MaxMatches>limits.MaxFind || req.MaxMatches>limits.MaxNodes {return out,errors.New("max_matches exceeds policy")}
    since,err:=DateSince(req.Since)
    if err!=nil {return out,err}
    root,err:=graph.GetAsset(ctx,req.StartID)
    if err!=nil {return out,err}
    out.Root=root
    out.VisitedNodes=1

    transitions:=make(map[string]bool)
    knownTypes:=make(map[string]bool)
    for _,t:=range catalog.Relations() {
        transitions[t.SourceType+"\x00"+t.Label+"\x00"+t.RelationType+"\x00"+t.DestinationType]=true
        knownTypes[t.SourceType]=true
        knownTypes[t.DestinationType]=true
    }
    if selectors,ok:=catalog.(AssetSearchCatalog); ok {
        for _,s:=range selectors.SearchFields() {knownTypes[s.Type]=true}
    }
    if !knownTypes[root.Type] {return out,fmt.Errorf("unregistered OAM root asset type %q",root.Type)}
    if len(req.TargetTypes)>100 {return out,errors.New("too many target types")}
    targets:=map[string]bool{}
    for _,typ:=range req.TargetTypes {
        if !knownTypes[typ] {return out,fmt.Errorf("unregistered OAM target asset type %q",typ)}
        targets[typ]=true
    }

    queue:=[]graphSearchStep{{asset:root,path:PlanMatch{Nodes:[]Asset{root}}}}
    visited:=map[string]bool{root.ID:true}
    edgeIDs:=map[string]bool{}
    assets:=map[string]Asset{root.ID:root}
    for len(queue)>0 {
        if err:=ctx.Err();err!=nil{return out,err}
        current:=queue[0]
        queue=queue[1:]
        if current.depth>=req.MaxDepth {continue}
        edges,more,err:=bounded.EdgesLimited(ctx,current.asset.ID,req.Direction,"",since,limits.MaxPerNode)
        if err!=nil {return out,err}
        if len(edges)>limits.MaxPerNode {return out,errors.New("bounded graph adapter violated row limit")}
        if more {out.Truncated=true;out.Reason="per-node edge limit"}
        sort.Slice(edges,func(i,j int)bool{return edges[i].ID<edges[j].ID})
        for _,edge:=range edges {
            if err:=ctx.Err();err!=nil{return out,err}
            nextID:=""
            switch {
            case current.asset.ID==edge.FromID && req.Direction!="in": nextID=edge.ToID
            case current.asset.ID==edge.ToID && req.Direction!="out": nextID=edge.FromID
            }
            if nextID=="" {return out,fmt.Errorf("edge %q is not incident in requested direction",edge.ID)}
            if !edgeIDs[edge.ID] {
                if out.VisitedEdges>=limits.MaxEdges {out.Truncated=true;out.Reason="edge limit";return out,nil}
                edgeIDs[edge.ID]=true
                out.VisitedEdges++
            }
            next,ok:=assets[nextID]
            if !ok {
                if len(assets)>=limits.MaxNodes {out.Truncated=true;out.Reason="node limit";return out,nil}
                next,err=graph.GetAsset(ctx,nextID)
                if err!=nil {return out,err}
                assets[nextID]=next
            }
            fromType,toType:=current.asset.Type,next.Type
            if edge.FromID==next.ID && edge.ToID==current.asset.ID {fromType,toType=toType,fromType}
            if !transitions[fromType+"\x00"+edge.Label+"\x00"+edge.Type+"\x00"+toType] {
                out.SchemaRejected++
                continue
            }
            if visited[nextID] {continue}
            if len(visited)>=limits.MaxNodes {out.Truncated=true;out.Reason="node limit";return out,nil}
            visited[nextID]=true
            out.VisitedNodes++
            path:=PlanMatch{Nodes:append(append([]Asset{},current.path.Nodes...),next),
                Edges:append(append([]Relation{},current.path.Edges...),edge)}
            if len(targets)==0 || targets[next.Type] {
                out.Matches=append(out.Matches,path)
                if len(out.Matches)>=req.MaxMatches {
                    out.Truncated=true
                    out.Reason="match limit"
                    return out,nil
                }
            }
            queue=append(queue,graphSearchStep{asset:next,path:path,depth:current.depth+1})
        }
    }
    if out.SchemaRejected>0 && !out.Truncated {
        out.Truncated=true
        out.Reason="stored relationships absent from OAM taxonomy"
    }
    out.Exhausted=!out.Truncated
    return out,nil
}
