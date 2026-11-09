// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
)

// SourceRecord describes a tag attached to one exact OAM graph relation.
// It is evidence OF a stored assertion, not independent verification that
// the assertion is true. Only typed SourceProperty tags have SourceID.
type SourceRecord struct {
	EvidenceID string    `json:"evidence_id"`
	EdgeID     string    `json:"edge_id"`
	SourceID   string    `json:"source_id,omitempty"`
	Kind       string    `json:"kind"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
}

type EdgeEvidence struct {
	EdgeID            string         `json:"edge_id"`
	Label             string         `json:"label"`
	FromID            string         `json:"from_id"`
	ToID              string         `json:"to_id"`
	Status            string         `json:"status"`
	AttributedSources []string       `json:"attributed_sources"`
	UnattributedTags  int            `json:"unattributed_tags"`
	Records           []SourceRecord `json:"records"`
	Truncated         bool           `json:"truncated"`
}

// PathEvidence describes source-level support for each hop in a specific
// witnessed path, not for the destination asset generically.
type PathEvidence struct {
	PathID            string         `json:"path_id"`
	Edges             []EdgeEvidence `json:"edges"`
	Status            string         `json:"status"`
	WeakestLink       string         `json:"weakest_link,omitempty"`
	VerifiedOwnership bool           `json:"verified_ownership"`
}

// EvidenceDossier is intentionally conservative: even multiple source tags
// can originate from the same upstream data and are not proof of independent
// corroboration. Reports never create an OAM relationship or confidence score.
type EvidenceDossier struct {
	Paths               []PathEvidence `json:"paths"`
	InspectedEdges      int            `json:"inspected_edges"`
	EdgeLookupsLimit    int            `json:"edge_lookups_limit"`
	RecordsPerEdgeLimit int            `json:"records_per_edge_limit"`
	Truncated           bool           `json:"truncated"`
	Reason              string         `json:"reason,omitempty"`
}

// EvaluatePathEvidence gathers up to 8 records per stored edge, with at most
// 40 different edge lookups, across a bounded candidate set. It does not
// accept a model-supplied evidence list, and never treats generic asset tags
// as proof of a particular relationship.
func EvaluatePathEvidence(ctx context.Context, graph Graph, limits Limits, paths []PlanMatch) (EvidenceDossier, error) {
	out := EvidenceDossier{Paths: make([]PathEvidence, 0, len(paths)), EdgeLookupsLimit: min(40, limits.MaxEdges), RecordsPerEdgeLimit: min(8, limits.MaxEvidence)}
	if graph == nil {
		return out, fmt.Errorf("graph evidence interface required")
	}
	if err := limits.Validate(); err != nil {
		return out, err
	}
	reader, ok := graph.(EdgeEvidenceReader)
	if !ok {
		return out, fmt.Errorf("explicit edge evidence reader required (asset and edge identifiers can overlap)")
	}
	if len(paths) > limits.MaxFind {
		return out, fmt.Errorf("path evidence request exceeds bounded find limit")
	}
	cache := map[string]EdgeEvidence{}
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		report := PathEvidence{PathID: p.PathID, Edges: make([]EdgeEvidence, 0, len(p.Edges))}
		if report.PathID == "" {
			report.PathID = WitnessPathID(p)
		}
		if len(p.Edges)+1 != len(p.Nodes) {
			return out, fmt.Errorf("malformed witnessed path %s", report.PathID)
		}
		worst := ""
		good := true
		for _, edge := range p.Edges {
			item, ok := cache[edge.ID]
			if !ok {
				item = EdgeEvidence{EdgeID: edge.ID, Label: edge.Label, FromID: edge.FromID, ToID: edge.ToID,
					Status: "not_assessed", AttributedSources: []string{}, Records: []SourceRecord{}}
				if len(cache) >= out.EdgeLookupsLimit {
					item.Truncated = true
					out.Truncated = true
					out.Reason = "evidence edge lookup limit"
				} else {
					// Ask for an extra tag to distinguish a complete answer from a
					// truncated evidence record set. The graph adapter enforces bounds.
					records, err := reader.EdgeEvidence(ctx, edge.ID, out.RecordsPerEdgeLimit+1)
					if err != nil {
						return out, fmt.Errorf("read evidence for OAM edge %s: %w", edge.ID, err)
					}
					if len(records) > out.RecordsPerEdgeLimit {
						records = records[:out.RecordsPerEdgeLimit]
						item.Truncated = true
						out.Truncated = true
						if out.Reason == "" {
							out.Reason = "per-edge evidence record limit"
						}
					}
					sources := map[string]bool{}
					seen := map[string]bool{}
					for _, record := range records {
						if record.SubjectID != "" && record.SubjectID != edge.ID {
							return out, fmt.Errorf("evidence %q does not belong to edge %q", record.ID, edge.ID)
						}
						if record.ID == "" {
							return out, fmt.Errorf("evidence tag missing ID on edge %q", edge.ID)
						}
						if seen[record.ID] {
							continue
						}
						seen[record.ID] = true
						sourceID := ""
						if record.Kind == string(oam.SourceProperty) {
							sourceID = strings.TrimSpace(record.SourceID)
						}
						tag := SourceRecord{EvidenceID: record.ID, EdgeID: edge.ID, SourceID: sourceID, Kind: record.Kind, LastSeen: record.LastSeen}
						item.Records = append(item.Records, tag)
						if tag.SourceID == "" {
							item.UnattributedTags++
						} else {
							sources[tag.SourceID] = true
						}
					}
					for src := range sources {
						item.AttributedSources = append(item.AttributedSources, src)
					}
					sort.Strings(item.AttributedSources)
					switch len(item.AttributedSources) {
					case 0:
						item.Status = "no_attributed_sources"
					case 1:
						item.Status = "single_source"
					default:
						item.Status = "multiple_source_tags"
					}
					out.InspectedEdges++
				}
				cache[edge.ID] = item
			}
			report.Edges = append(report.Edges, item)
			if item.Truncated || item.Status == "not_assessed" || item.Status == "no_attributed_sources" || item.Status == "single_source" {
				good = false
				if worst == "" {
					worst = edge.ID
				}
			}
		}
		if len(report.Edges) == 0 {
			report.Status = "no_edges"
		} else if good {
			report.Status = "multiple_source_tags_on_each_edge"
		} else {
			report.Status = "limited_source_support"
		}
		report.WeakestLink = worst
		out.Paths = append(out.Paths, report)
	}
	return out, nil
}
