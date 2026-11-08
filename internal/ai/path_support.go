// SPDX-License-Identifier: Apache-2.0
package ai

import "sort"

// EdgeSourceSummary exposes the exact stored provenance of one witnessed edge
// without presenting named sources as proof of independent corroboration.
type EdgeSourceSummary struct {
 EdgeID string `json:"edge_id"`
 Label string `json:"label"`
 Status string `json:"status"`
 SourceIDs []string `json:"source_ids"`
}

type PathSourceCoverage struct {
 AttributedEdges int `json:"attributed_edges"`
 MultiSourceTagEdges int `json:"multi_source_tag_edges"`
 MissingSourceEdges int `json:"missing_source_edges"`
 UnassessedEdges int `json:"unassessed_edges"`
 TotalEdges int `json:"total_edges"`
}

// pathSourceCoverage deliberately counts TAG COVERAGE, not source quality.
// Neither this tuple nor the display order is a calibrated confidence score.
func pathSourceCoverage(p PathEvidence) (PathSourceCoverage, []EdgeSourceSummary) {
 v:=PathSourceCoverage{TotalEdges:len(p.Edges)}
 out:=make([]EdgeSourceSummary,0,len(p.Edges))
 for _,edge:=range p.Edges {
  ids:=append([]string(nil),edge.AttributedSources...)
  sort.Strings(ids)
  out=append(out,EdgeSourceSummary{
   EdgeID:edge.EdgeID,Label:edge.Label,Status:edge.Status,SourceIDs:ids,
  })
  switch {
  case edge.Truncated||edge.Status=="not_assessed":
   v.UnassessedEdges++
  case len(ids)==0:
   v.MissingSourceEdges++
  default:
   v.AttributedEdges++
   if len(ids)>1{v.MultiSourceTagEdges++}
  }
 }
 return v,out
}

// rankComparableAlternates returns a deterministic ordering of exactly the
// same witnessed candidates. The evidence preference ONLY compares paths
// reaching the same destination asset: unrelated destinations are sorted by
// asset ID, never ranked for factual relevance by source-tag counts.
//
// Fewer unassessed edges take priority; then coverage of every path edge,
// then more multiply-tagged edges, then fewer hops, then stable path ID.
// A higher rank is NOT a claim of provenance independence or graph truth.
func rankComparableAlternates(items []adaptiveCandidate) {
 sort.SliceStable(items,func(i,j int)bool{
  a,b:=items[i],items[j]
  if a.AssetID!=b.AssetID{return a.AssetID<b.AssetID}
  x,y:=a.Coverage,b.Coverage
  if x.UnassessedEdges!=y.UnassessedEdges{return x.UnassessedEdges<y.UnassessedEdges}
  // Prefer the fraction of edges with at least one named source, avoiding
  // a bias toward longer paths purely because they contain more tags.
  left,right:=x.AttributedEdges*y.TotalEdges,y.AttributedEdges*x.TotalEdges
  if left!=right{return left>right}
  if x.MultiSourceTagEdges!=y.MultiSourceTagEdges{return x.MultiSourceTagEdges>y.MultiSourceTagEdges}
  if a.Depth!=b.Depth{return a.Depth<b.Depth}
  return a.PathID<b.PathID
 })
}
