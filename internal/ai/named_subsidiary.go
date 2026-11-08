// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// A narrow deterministic path for explicit direct-subsidiary questions.
// It deliberately does not claim to parse arbitrary natural language.
var directSubsidiariesQuestion = regexp.MustCompile(`(?i)^\s*(?:what|which)\s+(?:direct\s+)?subsidiar(?:y|ies)\s+does\s+(.+?)\s+have\s*\??\s*$`)

func (a Agent) answerDirectSubsidiaries(ctx context.Context, question string) (Investigation, bool, error) {
	matches := directSubsidiariesQuestion.FindStringSubmatch(question)
	if matches == nil {
		return Investigation{}, false, nil
	}
	result := Investigation{}
	name := strings.TrimSpace(matches[1])
	if name == "" {
		return result, true, errors.New("organization name missing")
	}
	lookupJSON, _ := json.Marshal(map[string]any{"name": name, "limit": 10})
	raw, err := a.Runner.Run(ctx, "lookup_organization", lookupJSON)
	if err != nil {
		result.Incomplete = true
		return result, true, fmt.Errorf("resolve named organization: %w", err)
	}
	result.ToolCalls++
	result.Observations = append(result.Observations, Observation{Tool: "lookup_organization", CallID: "deterministic-lookup", Result: string(raw)})
	var organizations []Asset
	if err := json.Unmarshal(raw, &organizations); err != nil {
		result.Incomplete = true
		return result, true, fmt.Errorf("decode organization lookup: %w", err)
	}
	if len(organizations) == 0 {
		result.Answer = fmt.Sprintf("No exact Organization name match for %q was found in this database. Subsidiary relationships cannot be determined.", name)
		result.Incomplete = true
		return result, true, nil
	}
	if len(organizations) != 1 {
		result.Answer = fmt.Sprintf("The name %q matches %d organizations. Specify an OAM entity ID to resolve the ambiguity.", name, len(organizations))
		result.Incomplete = true
		return result, true, nil
	}
	root := organizations[0]
	walkJSON, _ := json.Marshal(WalkRequest{StartID: root.ID, Direction: "out", Label: "subsidiary", Depth: 1})
	walkRaw, err := a.Runner.Run(ctx, "walk_relations", walkJSON)
	if err != nil {
		result.Incomplete = true
		return result, true, fmt.Errorf("read subsidiary graph: %w", err)
	}
	result.ToolCalls++
	result.Observations = append(result.Observations, Observation{Tool: "walk_relations", CallID: "deterministic-walk", Result: string(walkRaw)})
	var walk WalkResult
	if err := json.Unmarshal(walkRaw, &walk); err != nil {
		result.Incomplete = true
		return result, true, fmt.Errorf("decode graph traversal: %w", err)
	}
	byID := make(map[string]Asset, len(walk.Nodes))
	for _, asset := range walk.Nodes {
		byID[asset.ID] = asset
	}
	var children []string
	for _, edge := range walk.Edges {
		if edge.FromID != root.ID || edge.Label != "subsidiary" {
			result.Incomplete = true
			return result, true, errors.New("subsidiary traversal returned an unexpected relationship")
		}
		child, ok := byID[edge.ToID]
		if !ok || child.Type != "Organization" {
			result.Incomplete = true
			return result, true, errors.New("subsidiary traversal omitted a related Organization")
		}
		childName := child.Key
		if record, ok := child.Content.(map[string]any); ok {
			if n, ok := record["name"].(string); ok && n != "" {
				childName = n
			}
		}
		children = append(children, fmt.Sprintf("%s (asset ID %s, edge ID %s)", childName, child.ID, edge.ID))
	}
	sort.Strings(children)
	result.Incomplete = walk.Truncated
	if len(children) == 0 {
		result.Answer = fmt.Sprintf("No direct subsidiary edges were found for %q (asset ID %s) in the current Asset Database. This does not prove the organization has no subsidiaries.", name, root.ID)
	} else {
		result.Answer = fmt.Sprintf("The Asset Database records %d direct subsidiary relationship(s) for %q (asset ID %s): %s. These are stored OAM relationships, not independently verified legal ownership.", len(children), name, root.ID, strings.Join(children, "; "))
	}
	if walk.Truncated {
		result.Answer += " Results were truncated; other subsidiaries may exist."
	}
	return result, true, nil
}
