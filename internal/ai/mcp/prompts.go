// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// serverInstructions tell any assistant connected over MCP what the server
// is and how to use it. Clients show them to their model at connection.
const serverInstructions = `Amass MCP server: access to an OWASP Amass Asset Database (Open Asset Model) of a collected external attack surface: domains and host names, IP addresses and networks, autonomous systems, organizations, certificates, services, URLs, registrations and contacts.

How to answer questions:
1. Prefer the investigate tool. Pass a subject (a domain as {"type":"FQDN","field":"name","value":"example.com"}, or an organization as {"type":"Organization","name":"Example Inc"}) and the answer kind that fits the question; its description lists every kind. It returns the computed answer with numbered evidence items E1, E2, ...
2. Use the graph tools (resolve_asset, resolve_organization, find_assets, walk_relations and the others) to find the exact name of a subject, or to look at specific assets and relationships the answer kinds do not cover.
3. Cite evidence items like [E1] for every claim, and run verify_citations on your final prose with the investigation_id before presenting it.
4. To show how a domain's or organization's assets connect, call visualize and put its mermaid text in a mermaid code block; give the user its interactive link when there is one.
5. Report only what the database stores. Results come from past enumerations, not live scans; say so. A large footprint is sampled across kinds of asset up to a limit; when a result is partial, say so and offer to run it again with a larger max_assets.`

// readOnlyInstructions end the instructions of a connection without the
// operator token.
const readOnlyInstructions = `

This connection is read-only: it never writes to the database and never starts an enumeration. When the user wants data collected, tell them an operator connection (the operator token) can plan and start enumerations they approve.`

// promptPrefix names the server's prompts so they group together in
// clients that list prompts from several servers.
const promptPrefix = "amass_"

// overviewPrompt runs several answer kinds and summarizes them.
const overviewPrompt = promptPrefix + "attack_surface_overview"

// overviewKinds are the answer kinds the overview prompt asks for, in
// order, when the server offers them.
var overviewKinds = []string{lens.LensExposure, lens.LensServices, lens.LensNetwork, lens.LensDomains, lens.LensEmail,
	lens.LensCertificates, lens.LensDangling, lens.LensThirdParty}

// addPrompts offers one prompt per answer kind that needs only a subject,
// and an overview, so assistants that show MCP prompts as commands can run
// each lens by name.
func addPrompts(server *mcp.Server) {
	kinds := ai.SubjectAnswerKinds()
	arg := []*mcp.PromptArgument{{Name: "subject", Title: "Domain or organization", Required: true,
		Description: "A registered domain such as example.com, or an organization's name"}}

	var offered []string
	for _, k := range kinds {
		kind := k
		offered = append(offered, kind.Name)
		server.AddPrompt(&mcp.Prompt{
			Name:        promptName(kind.Name),
			Title:       "Amass: " + strings.ReplaceAll(kind.Name, "_", " "),
			Description: firstSentence(kind.Description),
			Arguments:   arg,
		}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			subject, err := promptSubject(req)
			if err != nil {
				return nil, err
			}

			return promptResult(firstSentence(kind.Description), lensRequest(subject, []string{kind.Name})), nil
		})
	}

	// The report lens assembles the others into one answer; without it the
	// overview asks for several kinds.
	overview := []string{lens.LensReport}
	if !slices.Contains(offered, lens.LensReport) {
		overview = nil
		for _, k := range overviewKinds {
			if slices.Contains(offered, k) {
				overview = append(overview, k)
			}
		}
	}
	if len(overview) == 0 {
		return
	}

	server.AddPrompt(&mcp.Prompt{
		Name:        overviewPrompt,
		Title:       "Amass: attack surface overview",
		Description: "Summarize a domain's or organization's stored attack surface across several lenses",
		Arguments:   arg,
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		subject, err := promptSubject(req)
		if err != nil {
			return nil, err
		}

		return promptResult("Attack surface overview", lensRequest(subject, overview)), nil
	})
}

// promptName is the MCP prompt name of an answer kind.
func promptName(kind string) string {
	return promptPrefix + strings.NewReplacer("-", "_", " ", "_").Replace(kind)
}

// promptSubject reads the subject argument.
func promptSubject(req *mcp.GetPromptRequest) (string, error) {
	var subject string
	if req.Params != nil {
		subject = strings.TrimSpace(req.Params.Arguments["subject"])
	}
	if subject == "" {
		return "", fmt.Errorf("the subject argument (a domain or an organization's name) is required")
	}

	return subject, nil
}

// subjectJSON is the investigate subject for what a user typed: a single
// word with a dot and no spaces is a domain, anything else an organization.
func subjectJSON(subject string) string {
	v := struct {
		Type  string `json:"type"`
		Name  string `json:"name,omitempty"`
		Field string `json:"field,omitempty"`
		Value string `json:"value,omitempty"`
	}{Type: "Organization", Name: subject}
	if !strings.ContainsAny(subject, " \t") && strings.Contains(strings.Trim(subject, "."), ".") {
		v.Type, v.Name, v.Field, v.Value = "FQDN", "", "name", strings.ToLower(strings.Trim(subject, "."))
	}

	data, _ := json.Marshal(v)
	return string(data)
}

// lensRequest is the user message a prompt sends: which investigate calls
// to make and how to report them.
func lensRequest(subject string, kinds []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Using the Amass MCP server, tell me about %s.\n\n", subject)
	b.WriteString("Call the investigate tool")
	if len(kinds) > 1 {
		b.WriteString(" once for each of these answer kinds")
	}

	fmt.Fprintf(&b, " with subject %s:\n", subjectJSON(subject))
	for _, k := range kinds {
		fmt.Fprintf(&b, "- answer: %q\n", k)
	}

	b.WriteString("\nIf the subject is not found, say so and suggest the closest names investigate reports. " +
		"Summarize the findings most worth attention first, citing evidence items like [E1] from the matching " +
		"investigation for every claim, then run verify_citations on your summary. Say that the results come " +
		"from stored enumerations, not a live scan, and note any result marked partial.")
	return b.String()
}

func promptResult(description, text string) *mcp.GetPromptResult {
	return &mcp.GetPromptResult{Description: description,
		Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}}}
}

// firstSentence shortens a kind's description for a prompt list.
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i]
	}

	s = strings.TrimSuffix(strings.TrimSuffix(s, ". Read-only"), ".")
	return s
}
