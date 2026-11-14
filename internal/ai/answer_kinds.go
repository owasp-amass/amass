// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// AnswerPaths is the default answer kind: explore stored relationships and
// choose among the witnessed paths.
const AnswerPaths = "paths"

// AnswerHierarchy lists the FQDNs below an FQDN subject.
const AnswerHierarchy = TraversalHierarchy

// AnswerKind is one kind of answer the goal planner can choose. The goal
// schema's answer enum and the planner prompt are generated from
// answerKinds, so a new kind registered here becomes available to the
// model without any question-wording rules.
type AnswerKind struct {
	Name string
	// Description tells the planner when to choose the kind.
	Description string
	// Subjects lists the subject types the kind accepts; empty means any.
	Subjects []string
	// Targets says how the kind uses target_types.
	Targets string
	// Examples are question shapes that call for the kind, shown to the
	// planner as guidance on meaning, never matched against questions.
	Examples []string
	// OwnedTargets marks kinds whose target_types must be types an owner can
	// control; the prompt lists them from the semantics table.
	OwnedTargets bool
}

var answerKinds = []AnswerKind{
	{
		Name: AnswerPaths,
		Description: "Explore stored relationships from the subject and choose the witnessed paths that answer " +
			"the question. Use for connectivity, specific relationships and highest parent questions.",
		Targets: "the asset types the answer is about, or [] to explore",
		Examples: []string{
			"How is <asset> connected to <organization>?",
			"What is the highest parent organization of <asset>?",
			"Which URLs are linked to <hostname> via domain relationships?",
		},
	},
	{
		Name:        AnswerHierarchy,
		Description: "List every name below the subject in the stored DNS name hierarchy (subdomain inventories).",
		Subjects:    []string{"FQDN"},
		Targets:     `["FQDN"]`,
		Examples: []string{
			"What subdomains does <domain> have?",
			"List the hostnames in <organization>'s DNS namespace.",
		},
	},
	{
		Name: lens.LensControlled,
		Description: "List the assets the subject owns or controls (networks, autonomous systems, domains, " +
			"certificates, accounts), attributed through registration, contact, website and subsidiary " +
			"relationships.",
		Subjects:     []string{"Organization", "FQDN"},
		Targets:      "the asset types to list, or [] for all controlled assets",
		OwnedTargets: true,
		Examples: []string{"Which ASN is associated with <organization>?", "What netblocks does <organization> have?",
			"Which domains belong to <organization>?"},
	},
	{
		Name: lens.LensThirdParty,
		Description: "List the outside parties the subject's controlled assets depend on: vendors, suppliers, " +
			"service providers, registrars, DNS and hosting networks, certificate authorities and software.",
		Subjects: []string{"Organization", "FQDN"},
		Targets:  "[]",
		Examples: []string{"Which vendors does <organization> use?", "Who hosts or provides services for <domain>?"},
	},
	{
		Name: lens.LensTable,
		Description: "Build a table with one row per asset of the single target type that the subject controls " +
			"and one column per entry of columns. Columns form a chain: the first follows from the row asset " +
			"and each later one from the previous column. {\"type\":T,\"role\":\"\"} is the nearest asset of type T " +
			"(for example the IP address of a URL or FQDN); {\"type\":\"Organization\",\"role\":\"controller\"} " +
			"is the organization that controls or operates the previous column's asset (for example the hosting " +
			"provider of an IP address).",
		Subjects: []string{"Organization", "FQDN"},
		Targets: "exactly one row type: the kind of asset each row is (URL for websites, FQDN for host names, " +
			"Netblock for networks), never the subject's own type or a column's type",
		OwnedTargets: true,
		Examples: []string{
			"Table of each website of <organization> with its IP address and hosting provider -> target_types " +
				"[\"URL\"], columns [{\"type\":\"IPAddress\",\"role\":\"\"},{\"type\":\"Organization\"," +
				"\"role\":\"controller\"}]",
			"For each domain <organization> owns, show its IP addresses",
		},
	},
	{
		Name: LensFamily,
		Description: "Show the organization family of an enumerated domain: the organizations that are its " +
			"institution (name variants and departments) or affiliates, each with the evidence tying it to the " +
			"domain, the networks serving the domain's names, and other registered domains those networks serve. " +
			"Read-only; nothing is written.",
		Subjects: []string{"FQDN"},
		Targets:  "[]",
		Examples: []string{
			"Which organizations make up <domain>'s institution?",
			"What departments and affiliates does <domain> have?",
			"Which other domains belong to the same institution as <domain>?",
		},
	},
	{
		Name: lens.LensOrgGroup,
		Description: "Show the corporate group of an organization: its ultimate parent company and every " +
			"subsidiary and organizational unit below it, from stored corporate relationships, with each " +
			"organization's jurisdiction and registration. From a domain, the group of its main organization. " +
			"Read-only; nothing is written.",
		Subjects: []string{"Organization", "FQDN"},
		Targets:  "[]",
		Examples: []string{
			"Who owns <organization>?",
			"What companies are part of <organization>'s corporate group?",
			"What is the parent company of the organization behind <domain>?",
		},
	},
	{
		Name: lens.LensServices,
		Description: "List the services stored for what a domain or organization controls: where each listens, " +
			"its type, the software its responses name (identified product and version), its certificates, and " +
			"what stands out (unusual ports, expired or self-issued certificates). Services come from past probes, " +
			"not a live scan. Read-only; nothing is written.",
		Subjects: []string{"Organization", "FQDN"},
		Targets:  "[]",
		Examples: []string{
			"What services does <domain> expose?",
			"Which software and versions run on <organization>'s servers?",
			"Does <domain> have expired certificates or services on unusual ports?",
		},
	},
	{
		Name: lens.LensNetwork,
		Description: "Show the network infrastructure of what a domain or organization controls: its netblocks and " +
			"autonomous systems, where its names are hosted, unused space, other domains in its space. Read-only",
		Subjects: []string{"Organization", "FQDN"},
		Targets:  "[]",
		Examples: []string{
			"What network infrastructure does <organization> have?",
			"Which IP ranges and autonomous systems belong to <domain>?",
			"Where is <domain> hosted: its own networks or a cloud provider?",
		},
	},
	{
		Name: lens.LensChanges,
		Description: "Show what changed recently in what a domain or organization controls: records first stored in the last " +
			"30 days, and records later enumerations stopped seeing. Read-only",
		Subjects: []string{"Organization", "FQDN"},
		Targets:  "[]",
		Examples: []string{
			"What changed recently for <domain>?",
			"What new assets does <organization> have this month?",
			"Which of <domain>'s records disappeared lately?",
		},
	},
	{
		Name: lens.LensDangling,
		Description: "Find DNS records of what a domain or organization controls that may point at something it no longer " +
			"holds: aliases to deleted cloud resources (subdomain takeover), lapsed domains, stale addresses. Read-only",
		Subjects: []string{"Organization", "FQDN"},
		Targets:  "[]",
		Examples: []string{
			"Does <domain> have dangling DNS records?",
			"Which of <organization>'s subdomains could be taken over?",
			"Do any of <domain>'s CNAMEs point at deleted cloud resources?",
		},
	},
	{
		Name: lens.LensGroupVendors,
		Description: "List the outside parties a whole corporate group depends on: the vendors of each " +
			"organization in the group (parent, subsidiaries and units) merged, with how many and which group " +
			"organizations use each, and services one group organization provides another set apart. From a " +
			"domain, the group of its main organization. Read-only; nothing is written.",
		Subjects: []string{"Organization", "FQDN"},
		Targets:  "[]",
		Examples: []string{
			"Which vendors does <organization>'s corporate group depend on?",
			"What third parties do <organization> and its subsidiaries use?",
		},
	},
	{
		Name: lens.LensOwnershipGaps,
		Description: "Find assets with no documented owner that share identity (contact details), hosting (resolving " +
			"into its networks) or certificate signals with what the subject controls, each scored, with the OAM " +
			"relationship that would record the subject as owner. Proposals only; nothing is written.",
		Subjects: []string{"Organization", "FQDN"},
		Targets:  "[]",
		Examples: []string{
			"What assets might <organization> own that are not attributed to it?",
			"Which domains look like they belong to <organization> but have no documented owner?",
		},
	},
}

func answerKind(name string) (AnswerKind, bool) {
	if name == "" {
		name = AnswerPaths
	}
	for _, k := range answerKinds {
		if k.Name == name {
			return k, true
		}
	}

	return AnswerKind{}, false
}

func answerKindNames() []string {
	names := make([]string, 0, len(answerKinds))
	for _, k := range answerKinds {
		names = append(names, k.Name)
	}

	return names
}

// answerKindCatalog renders the answer kinds for the planner prompt.
func answerKindCatalog(owned []string) string {
	var b strings.Builder
	for _, k := range answerKinds {
		subjects := "any subject type"
		if len(k.Subjects) > 0 {
			subjects = "subject " + strings.Join(k.Subjects, " or ")
		}

		fmt.Fprintf(&b, "- %s (%s; target_types %s): %s", k.Name, subjects, k.Targets, k.Description)
		if k.OwnedTargets && len(owned) > 0 {
			fmt.Fprintf(&b, " Types an owner can control: %s.", strings.Join(owned, ", "))
		}
		if len(k.Examples) > 0 {
			fmt.Fprintf(&b, " Examples: %s", strings.Join(k.Examples, " | "))
		}

		b.WriteString("\n")
	}

	return b.String()
}

// validateAnswer checks the planner's answer kind against the subject,
// targets and purpose, and against the semantics table for lenses.
func validateAnswer(goal InvestigationGoal, schema graph.SchemaCatalog) error {
	k, ok := answerKind(goal.Answer)
	if !ok {
		return fmt.Errorf("unknown answer %q; choose one of %s", goal.Answer, strings.Join(answerKindNames(), ", "))
	}
	if k.Name == AnswerPaths {
		return nil
	}
	if goal.Purpose == "ultimate_parent" {
		return fmt.Errorf("purpose ultimate_parent uses answer %q", AnswerPaths)
	}
	if len(k.Subjects) > 0 && !contains(k.Subjects, goal.Subject.Type) {
		return fmt.Errorf("answer %q needs a %s subject, not %s", k.Name, strings.Join(k.Subjects, " or "),
			goal.Subject.Type)
	}
	switch k.Name {
	case AnswerHierarchy:
		if len(goal.TargetTypes) > 1 || (len(goal.TargetTypes) == 1 && goal.TargetTypes[0] != "FQDN") {
			return fmt.Errorf("answer %q lists FQDNs; use target_types [\"FQDN\"]", k.Name)
		}
	case lens.LensControlled:
		if graph.MeaningsOf(schema) == nil {
			return fmt.Errorf("answer %q needs relationship semantics", k.Name)
		}
		if len(goal.TargetTypes) > 0 && !lens.ControlledReachable(schema, goal.TargetTypes) {
			return fmt.Errorf("answer %q lists asset types that can be attributed to an owner; %v cannot be. "+
				"Types an owner can control: %s. Otherwise use answer %q", k.Name, goal.TargetTypes,
				strings.Join(lens.OwnedTypes(schema), ", "), AnswerPaths)
		}
	case lens.LensThirdParty, lens.LensOwnershipGaps, LensFamily, lens.LensOrgGroup, lens.LensServices, lens.LensGroupVendors,
		lens.LensNetwork, lens.LensDangling, lens.LensChanges:
		if graph.MeaningsOf(schema) == nil {
			return fmt.Errorf("answer %q needs relationship semantics", k.Name)
		}
	case lens.LensTable:
		if len(goal.TargetTypes) != 1 {
			return fmt.Errorf("answer %q needs exactly one row type in target_types", k.Name)
		}
		if !lens.ControlledReachable(schema, goal.TargetTypes) {
			return fmt.Errorf("answer %q: target_types holds the row type, the kind of asset each row is "+
				"(URL for websites, FQDN for host names, Netblock for networks); %s cannot be a row. Row types an "+
				"owner can control: %s. Keep the organization in subject and put providers or owners in columns "+
				"with role controller", k.Name, goal.TargetTypes[0], strings.Join(lens.OwnedTypes(schema), ", "))
		}
		if err := lens.ValidateColumns(goal.Columns, graph.CatalogTypes(schema.Relations(), nil)); err != nil {
			return fmt.Errorf("answer %q: %w", k.Name, err)
		}
	}

	return nil
}

// queryFromPlannedGoal turns a validated planner goal into a Query for its
// answer kind.
//
// Two goal structures are answered deterministically whatever kind the
// model chose: a goal that follows only the FQDN node hierarchy is a
// hierarchy listing, and an unconstrained connected goal from an
// Organization to asset types the semantics table can attribute to an
// owner is the controlled lens, which reads the same attribution paths
// without model path selection.
func queryFromPlannedGoal(goal InvestigationGoal, question string, schema graph.SchemaCatalog) Query {
	q := QueryFromGoal(goal, question, SourceModelGoal)
	switch goal.Answer {
	case AnswerHierarchy:
		hierarchyQuery(&q)
	case lens.LensControlled:
		q = Query{Version: QueryVersion, Question: question, Subject: goal.Subject, Traversal: TraversalExplore,
			TargetTypes: append([]string(nil), goal.TargetTypes...), Direction: "both", Purpose: "connected",
			Lens: lens.LensControlled, Source: SourceModelGoal}
	case lens.LensThirdParty:
		q = thirdPartyQuery(question, goal.Subject, SourceModelGoal)
	case lens.LensOwnershipGaps, LensFamily, lens.LensOrgGroup, lens.LensServices, lens.LensGroupVendors,
		lens.LensNetwork, lens.LensDangling, lens.LensChanges:
		q = thirdPartyQuery(question, goal.Subject, SourceModelGoal)
		q.Lens = goal.Answer
	case lens.LensTable:
		q = Query{Version: QueryVersion, Question: question, Subject: goal.Subject, Traversal: TraversalExplore,
			TargetTypes: append([]string(nil), goal.TargetTypes...), Direction: "both", Purpose: "connected",
			Lens: lens.LensTable, Columns: tableColumns(goal, mentionedTypes(question, schema)), Source: SourceModelGoal}
	default:
		if goal.Subject.Type == "Organization" && goal.Purpose == "connected" && len(goal.Relationships) == 0 &&
			lens.ControlledReachable(schema, goal.TargetTypes) {
			goal.Answer = lens.LensControlled
			return queryFromPlannedGoal(goal, question, schema)
		}

		promoteHierarchyGoal(&q)
	}

	return q
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}

	return false
}

// tableColumns normalizes a planned column chain. It drops leading columns
// that only repeat the row asset (a URL column in a table of URLs), and
// adds a column for each asset type the question mentions that the chain
// leaves out, before the first controller column so that the controller
// describes it (a question naming IP addresses and hosting providers gets
// the IP address column the provider column needs). Mentions come from the
// vocabulary data; the subject's and row's types and Organization (the
// subject or a controller) are never added.
func tableColumns(goal InvestigationGoal, mentioned []string) []lens.TableColumn {
	cols := append([]lens.TableColumn(nil), goal.Columns...)
	for len(cols) > 1 && len(goal.TargetTypes) == 1 && cols[0].Role == lens.ColumnReached &&
		cols[0].Type == goal.TargetTypes[0] {
		cols = cols[1:]
	}

	present := map[string]bool{goal.Subject.Type: true, "Organization": true, "Person": true}
	for _, t := range goal.TargetTypes {
		present[t] = true
	}
	for _, c := range cols {
		present[c.Type] = true
	}

	var missing []lens.TableColumn
	for _, t := range mentioned {
		if !present[t] {
			present[t] = true
			missing = append(missing, lens.TableColumn{Type: t, Role: lens.ColumnReached})
		}
	}
	if len(missing) == 0 {
		return cols
	}

	at := len(cols)
	for i, c := range cols {
		if c.Role == lens.ColumnController {
			at = i
			break
		}
	}

	out := append(append(append([]lens.TableColumn(nil), cols[:at]...), missing...), cols[at:]...)
	if len(out) > lens.TableMaxColumns {
		return cols
	}

	return out
}

// mentionedTypes lists, sorted, the catalog asset types the question names
// through the vocabulary. Longer phrases claim their words first, so "IP
// address" names IPAddress and not also Location ("address").
func mentionedTypes(question string, schema graph.SchemaCatalog) []string {
	pos := mentionedTypePositions(question, schema)
	out := make([]string, 0, len(pos))
	for t := range pos {
		out = append(out, t)
	}

	sort.Strings(out)
	return out
}

// mentionedTypesInOrder returns the asset types a question mentions in the
// order it mentions them.
func mentionedTypesInOrder(question string, schema graph.SchemaCatalog) []string {
	pos := mentionedTypePositions(question, schema)
	out := make([]string, 0, len(pos))
	for t := range pos {
		out = append(out, t)
	}

	sort.Slice(out, func(i, j int) bool {
		if pos[out[i]] != pos[out[j]] {
			return pos[out[i]] < pos[out[j]]
		}

		return out[i] < out[j]
	})
	return out
}

// mentionedTypePositions finds the asset types a question names through
// their vocabulary aliases, longest alias first, with where each is first
// named.
func mentionedTypePositions(question string, schema graph.SchemaCatalog) map[string]int {
	found := map[string]int{}
	if schema == nil {
		return found
	}

	type alias struct{ words, kind string }
	var aliases []alias
	for kind := range graph.CatalogTypes(schema.Relations(), nil) {
		for _, a := range intentAssetAliases(kind) {
			if n := normalizeSchemaAlias(a); n != "" {
				aliases = append(aliases, alias{words: n, kind: kind})
			}
		}
	}

	sort.Slice(aliases, func(i, j int) bool {
		if len(aliases[i].words) != len(aliases[j].words) {
			return len(aliases[i].words) > len(aliases[j].words)
		}

		return aliases[i].words < aliases[j].words
	})

	text := " " + normalizeSchemaAlias(question) + " "
	for _, a := range aliases {
		needle := " " + a.words + " "
		if i := strings.Index(text, needle); i >= 0 {
			if prev, ok := found[a.kind]; !ok || i < prev {
				found[a.kind] = i
			}
			// Blank the phrase so shorter aliases inside it cannot match.
			text = text[:i+1] + strings.Repeat("#", len(a.words)) + text[i+1+len(a.words):]
		}
	}

	return found
}

// repairRowType fixes a table whose row type an owner cannot control (the
// controller itself, typically) without another model call: the rows become
// the first type the question mentions that an owner can control, as in
// "a table with each website, its IP address and hosting provider".
func repairRowType(goal InvestigationGoal, question string, schema graph.SchemaCatalog) InvestigationGoal {
	k, ok := answerKind(goal.Answer)
	if !ok || k.Name != lens.LensTable || schema == nil {
		return goal
	}
	if len(goal.TargetTypes) == 1 && lens.ControlledReachable(schema, goal.TargetTypes) {
		return goal
	}
	for _, t := range mentionedTypesInOrder(question, schema) {
		if t != "Organization" && lens.ControlledReachable(schema, []string{t}) {
			goal.TargetTypes = []string{t}
			return goal
		}
	}

	return goal
}

// narrowGoalSchema returns base restricted to one answer kind, for the retry
// after the planner chose that kind but filled it in wrongly: the answer is
// fixed, the subject types are the kind's, target_types allow only what the
// kind can list (for controlled and table, the types an owner can control,
// from the semantics table), and fields the kind does not use must be
// empty. A provider that enforces schemas then cannot repeat the mistake.
func narrowGoalSchema(base llm.JSONSchema, kind AnswerKind, schema graph.SchemaCatalog) llm.JSONSchema {
	props := map[string]any{}
	for k, v := range base.Schema["properties"].(map[string]any) {
		props[k] = v
	}

	none := map[string]any{"type": "array", "maxItems": 0}
	enumArray := func(values []string, min, max int) map[string]any {
		a := map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": values}}
		if min > 0 {
			a["minItems"] = min
		}
		if max > 0 {
			a["maxItems"] = max
		}

		return a
	}

	props["answer"] = map[string]any{"type": "string", "enum": []string{kind.Name}}
	if len(kind.Subjects) > 0 {
		subject := map[string]any{}
		for k, v := range props["subject"].(map[string]any) {
			subject[k] = v
		}

		fields := map[string]any{}
		for k, v := range subject["properties"].(map[string]any) {
			fields[k] = v
		}

		fields["type"] = map[string]any{"type": "string", "enum": kind.Subjects}
		subject["properties"] = fields
		props["subject"] = subject
	}
	if kind.Name != AnswerPaths {
		props["purpose"] = map[string]any{"type": "string", "enum": []string{"connected"}}
		props["relationships"] = none
		props["path_rule"] = map[string]any{"type": "string", "enum": []string{""}}
	}

	owned := lens.OwnedTypes(schema)
	switch kind.Name {
	case AnswerHierarchy:
		props["target_types"] = enumArray([]string{"FQDN"}, 0, 1)
	case lens.LensControlled:
		props["target_types"] = enumArray(owned, 0, 0)
	case lens.LensThirdParty, lens.LensOwnershipGaps, LensFamily, lens.LensOrgGroup, lens.LensServices, lens.LensGroupVendors,
		lens.LensNetwork, lens.LensDangling, lens.LensChanges:
		props["target_types"] = none
	case lens.LensTable:
		props["target_types"] = enumArray(owned, 1, 1)
		if cols, ok := props["columns"].(map[string]any); ok {
			narrowed := map[string]any{}
			for k, v := range cols {
				narrowed[k] = v
			}

			narrowed["minItems"] = 1
			props["columns"] = narrowed
		}
	}
	if kind.Name != lens.LensTable {
		props["columns"] = none
	}

	out := map[string]any{}
	for k, v := range base.Schema {
		out[k] = v
	}

	out["properties"] = props
	return llm.JSONSchema{Name: base.Name, Description: base.Description + " Answer kind: " + kind.Name + ".",
		Schema: out}
}
