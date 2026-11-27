// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/viz"
)

// ToolVisualize draws a subject's controlled footprint.
const ToolVisualize = "visualize"

const (
	// vizMaxAssets bounds a footprint drawing.
	vizMaxAssets = 3000
	// vizDetailNodes is the largest graph drawn node by node in Mermaid.
	vizDetailNodes = 40
	vizLinkTTL     = time.Hour
	vizLinkPrefix  = "/viz/"
	maxVizLinks    = 128
)

// VizLinks serves interactive drawings of a subject's footprint at
// unguessable local links, so an assistant can hand the user a graph to
// explore in a browser or open in Gephi.
type VizLinks struct {
	BaseURL string
	Runner  ai.ToolRunner
	Now     func() time.Time

	mu    sync.Mutex
	links map[string]vizLink
}

type vizLink struct {
	subject string
	expires time.Time
}

func (v *VizLinks) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}

	return time.Now()
}

// New issues a link for a subject.
func (v *VizLinks) New(subject string) (string, error) {
	id := newSessionID()
	if id == "" || v.BaseURL == "" {
		return "", errors.New("links are not available")
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.links == nil {
		v.links = map[string]vizLink{}
	}
	for k, l := range v.links {
		if v.now().After(l.expires) {
			delete(v.links, k)
		}
	}
	if len(v.links) >= maxVizLinks {
		return "", errors.New("too many open drawing links; wait for them to expire")
	}

	v.links[id] = vizLink{subject: subject, expires: v.now().Add(vizLinkTTL)}
	return strings.TrimSuffix(v.BaseURL, "/") + vizLinkPrefix + id, nil
}

// ServeHTTP renders a link as a D3 page, or as GEXF with a .gexf suffix.
func (v *VizLinks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet || !validOrigin(r) {
		http.Error(w, "not allowed", http.StatusForbidden)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, vizLinkPrefix)
	gexf := strings.HasSuffix(id, ".gexf")
	id = strings.TrimSuffix(id, ".gexf")
	v.mu.Lock()
	l, ok := v.links[id]
	v.mu.Unlock()
	if !ok || v.now().After(l.expires) {
		http.Error(w, "this drawing link has expired; ask your assistant for a new one", http.StatusNotFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	nodes, edges, _, err := footprint(ctx, v.Runner, l.subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if gexf {
		w.Header().Set("Content-Type", "application/gexf+xml")
		w.Header().Set("Content-Disposition", `attachment; filename="amass-footprint.gexf"`)
		_ = viz.WriteGEXFData(w, nodes, edges)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = viz.WriteD3Data(w, nodes, edges)
}

// resolveSubject finds the asset a user names: a domain or an organization.
func resolveSubject(ctx context.Context, g graph.Graph, subject string) (graph.Asset, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return graph.Asset{}, errors.New("a subject (a domain or an organization's name) is required")
	}
	if !strings.ContainsAny(subject, " \t") && strings.Contains(strings.Trim(subject, "."), ".") {
		resolver, ok := g.(graph.AssetResolver)
		if !ok {
			return graph.Asset{}, errors.New("the database cannot look up names")
		}

		name := strings.ToLower(strings.Trim(subject, "."))
		res, err := resolver.ResolveAsset(ctx, graph.AssetSelector{Type: "FQDN", Field: "name", Value: name}, 1)
		if err != nil {
			return graph.Asset{}, err
		}
		if len(res.Candidates) == 0 {
			return graph.Asset{}, fmt.Errorf("%s is not in the database; enumerate it first", name)
		}

		return res.Candidates[0].Asset, nil
	}

	searcher, ok := g.(graph.OrgSearchGraph)
	if !ok {
		return graph.Asset{}, errors.New("the database cannot look up organizations")
	}

	// Shared resolve/suggest: one exact name is used directly; a misspelled or
	// partial name, or several same-name organizations, come back as ranked
	// candidates to choose from.
	res, err := graph.ResolveOrSuggest(ctx, searcher, subject, 5)
	if err != nil {
		return graph.Asset{}, err
	}
	switch res.Status {
	case graph.StatusMatched:
		return *res.Match, nil
	case graph.StatusSuggestions:
		names := make([]string, 0, len(res.Candidates))
		for _, c := range res.Candidates {
			label := c.Name
			if c.Jurisdiction != "" {
				label += " [" + c.Jurisdiction + "]"
			}
			names = append(names, label)
		}
		return graph.Asset{}, fmt.Errorf("no exact match for organization %q; did you mean: %s", subject,
			strings.Join(names, "; "))
	}

	return graph.Asset{}, fmt.Errorf("no organization matches %q", subject)
}

// footprint computes the drawing of a subject's controlled footprint.
func footprint(ctx context.Context, runner ai.ToolRunner, subject string) ([]viz.Node, []viz.Edge,
	lens.ControlledReport, error) {
	if runner.Graph == nil || runner.Catalog == nil {
		return nil, nil, lens.ControlledReport{}, errors.New("no database is configured")
	}

	root, err := resolveSubject(ctx, runner.Graph, subject)
	if err != nil {
		return nil, nil, lens.ControlledReport{}, err
	}

	report, err := lens.SearchControlled(ctx, runner.Graph, runner.Catalog, root, nil, vizMaxAssets, lens.LensLimits{})
	if err != nil {
		return nil, nil, report, err
	}

	nodes, edges := viz.FootprintGraph(report)
	return nodes, edges, report, nil
}

// visualizeCapability is the read-only footprint drawing tool; links is nil
// without an HTTP server to serve drawings.
func visualizeCapability(runner ai.ToolRunner, links *VizLinks) capability {
	desc := "Draw what a domain or organization controls as a Mermaid diagram: assets grouped by type with " +
		"counts and the relations joining them, and every asset when there are few. Show the mermaid text to " +
		"the user in a mermaid code block."
	if links != nil {
		desc += " Also returns a link to an interactive graph and a GEXF file for Gephi, valid for an hour."
	}

	return capability{tier: tierRead, tool: &mcp.Tool{Name: ToolVisualize, Title: "Draw an Amass footprint",
		Description: desc,
		InputSchema: map[string]any{"type": "object", "required": []string{"subject"}, "additionalProperties": false,
			"properties": map[string]any{"subject": map[string]any{"type": "string",
				"description": "A domain such as example.com, or an organization's name"}}},
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPtr(false)}},
		handle: func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a struct{ Subject string }
			if req.Params != nil && len(req.Params.Arguments) > 0 {
				if err := json.Unmarshal(req.Params.Arguments, &a); err != nil {
					return errorResult(err), nil
				}
			}

			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			nodes, edges, report, err := footprint(ctx, runner, a.Subject)
			if err != nil {
				return errorResult(err), nil
			}

			out := map[string]any{"subject": graph.AssetLabel(report.Root), "assets": len(nodes),
				"relations": len(edges), "mermaid": viz.MermaidSummary(nodes, edges)}
			if detail := viz.MermaidDetail(nodes, edges, vizDetailNodes); detail != "" {
				out["mermaid_detail"] = detail
			}
			if report.Truncated {
				out["partial"] = report.Reason
			}
			if links != nil {
				if link, err := links.New(a.Subject); err == nil {
					out["interactive_url"] = link
					out["gexf_url"] = link + ".gexf"
				}
			}

			return jsonResult(out), nil
		},
	}
}
