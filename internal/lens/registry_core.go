// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// The services, network, dangling DNS and changes lenses predate the
// registry; registering them makes each an amass lens command, an answer
// kind and an MCP prompt like the others.

var servicesLens = SubjectLens{
	Name:    LensServices,
	Command: "services",
	Description: "List the services stored for what a domain or organization controls: where each listens, the " +
		"software it names, its certificates and what stands out. From past probes, not a live scan. Read-only",
	Examples: []string{"What services does <domain> expose?",
		"Which software and versions run on <organization>'s servers?",
		"Does <domain> have expired certificates or services on unusual ports?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindServices(ctx, g, schema, root, opts.Limits)
	},
}

var networkLens = SubjectLens{
	Name:    LensNetwork,
	Command: "network",
	Description: "Show the network infrastructure of what a domain or organization controls: its netblocks and " +
		"autonomous systems, where its names are hosted, unused space, other domains in its space. Read-only",
	Examples: []string{"What network infrastructure does <organization> have?",
		"Which IP ranges and autonomous systems belong to <domain>?",
		"Where is <domain> hosted: its own networks or a cloud provider?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindNetworkInfrastructure(ctx, g, schema, root, opts.Limits)
	},
}

var danglingLens = SubjectLens{
	Name:    LensDangling,
	Command: "dangling",
	Description: "Find DNS records of what a domain or organization controls that may point at something it no " +
		"longer holds: aliases to deleted cloud resources (takeover), lapsed domains, stale addresses. Read-only",
	Examples: []string{"Does <domain> have dangling DNS records?",
		"Which of <organization>'s subdomains could be taken over?",
		"Do any of <domain>'s CNAMEs point at deleted cloud resources?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindDanglingDNS(ctx, g, schema, root, opts.Limits)
	},
}

var changesLens = SubjectLens{
	Name:    LensChanges,
	Command: "changes",
	Description: "Show what changed recently in what a domain or organization controls: records first stored in " +
		"the last 30 days, and records later enumerations stopped seeing. Read-only",
	Examples: []string{"What changed recently for <domain>?",
		"What new assets does <organization> have this month?",
		"Which of <domain>'s records disappeared lately?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindChanges(ctx, g, schema, root, opts.Since, opts.Limits)
	},
}

// Text implements Report.
func (r ServicesReport) Text() string { return FormatServicesReport(r) }

// Facts implements Report: the software each service runs, and its type and
// endpoints.
func (r ServicesReport) Facts() []string {
	var out []string
	for _, s := range r.Services {
		for _, p := range s.Identified {
			out = append(out, strings.TrimSpace("runs "+p.Product+" "+p.Version))
		}

		out = append(out, s.ServiceType+" "+strings.Join(s.Endpoints, ", "))
	}

	return out
}

// Partial implements Report.
func (r ServicesReport) Partial() (bool, string) { return r.Truncated, r.Reason }

// Text implements Report.
func (r NetworkReport) Text() string { return FormatNetworkReport(r) }

// Facts implements Report: the subject's netblocks, autonomous systems and
// hosting parties.
func (r NetworkReport) Facts() []string {
	var out []string
	for _, n := range r.Networks {
		out = append(out, n.CIDR)
	}
	for _, as := range r.ASNs {
		out = append(out, as.Number)
	}
	for _, h := range r.Hosting {
		out = append(out, "hosted by "+h.Party)
	}

	return out
}

// Partial implements Report.
func (r NetworkReport) Partial() (bool, string) { return r.Truncated, r.Reason }

// Text implements Report.
func (r DanglingReport) Text() string { return FormatDanglingReport(r) }

// Facts implements Report: each finding's kind, name and target. The report
// lens matches its key findings on the kind.
func (r DanglingReport) Facts() []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.Kind+" "+f.Name+" -> "+f.Target)
	}

	return out
}

// Partial implements Report.
func (r DanglingReport) Partial() (bool, string) { return r.Truncated, r.Reason }

// Text implements Report.
func (r ChangesReport) Text() string { return FormatChangesReport(r) }

// Facts implements Report: examples of what is new and what went quiet.
func (r ChangesReport) Facts() []string {
	var out []string
	for _, groups := range [][]ChangeGroup{r.NewAssets, r.NewRelations, r.QuietAssets, r.QuietRelations} {
		for _, g := range groups {
			out = append(out, g.Examples...)
		}
	}

	return out
}

// Partial implements Report.
func (r ChangesReport) Partial() (bool, string) { return r.Truncated, r.Reason }
