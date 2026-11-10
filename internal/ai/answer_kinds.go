// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"sort"
	"strings"
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
		Name: LensControlled,
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
		Name: LensThirdParty,
		Description: "List the outside parties the subject's controlled assets depend on: vendors, suppliers, " +
			"service providers, registrars, DNS and hosting networks, certificate authorities and software.",
		Subjects: []string{"Organization", "FQDN"},
		Targets:  "[]",
		Examples: []string{"Which vendors does <organization> use?", "Who hosts or provides services for <domain>?"},
	},
	{
		Name: LensTable,
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
func validateAnswer(goal InvestigationGoal, schema SchemaCatalog) error {
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
	case LensControlled:
		if meaningsOf(schema) == nil {
			return fmt.Errorf("answer %q needs relationship semantics", k.Name)
		}
		if len(goal.TargetTypes) > 0 && !controlledReachable(schema, goal.TargetTypes) {
			return fmt.Errorf("answer %q lists asset types that can be attributed to an owner; %v cannot be. "+
				"Types an owner can control: %s. Otherwise use answer %q", k.Name, goal.TargetTypes,
				strings.Join(ownedTypes(schema), ", "), AnswerPaths)
		}
	case LensThirdParty:
		if meaningsOf(schema) == nil {
			return fmt.Errorf("answer %q needs relationship semantics", k.Name)
		}
	case LensTable:
		if len(goal.TargetTypes) != 1 {
			return fmt.Errorf("answer %q needs exactly one row type in target_types", k.Name)
		}
		if !controlledReachable(schema, goal.TargetTypes) {
			return fmt.Errorf("answer %q: target_types holds the row type, the kind of asset each row is "+
				"(URL for websites, FQDN for host names, Netblock for networks); %s cannot be a row. Row types an "+
				"owner can control: %s. Keep the organization in subject and put providers or owners in columns "+
				"with role controller", k.Name, goal.TargetTypes[0], strings.Join(ownedTypes(schema), ", "))
		}
		if err := validateColumns(goal.Columns, catalogTypes(schema.Relations(), nil)); err != nil {
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
func queryFromPlannedGoal(goal InvestigationGoal, question string, schema SchemaCatalog) Query {
	q := QueryFromGoal(goal, question, SourceModelGoal)
	switch goal.Answer {
	case AnswerHierarchy:
		hierarchyQuery(&q)
	case LensControlled:
		q = Query{Version: QueryVersion, Question: question, Subject: goal.Subject, Traversal: TraversalExplore,
			TargetTypes: append([]string(nil), goal.TargetTypes...), Direction: "both", Purpose: "connected",
			Lens: LensControlled, Source: SourceModelGoal}
	case LensThirdParty:
		q = thirdPartyQuery(question, goal.Subject, SourceModelGoal)
	case LensTable:
		q = Query{Version: QueryVersion, Question: question, Subject: goal.Subject, Traversal: TraversalExplore,
			TargetTypes: append([]string(nil), goal.TargetTypes...), Direction: "both", Purpose: "connected",
			Lens: LensTable, Columns: tableColumns(goal, mentionedTypes(question, schema)), Source: SourceModelGoal}
	default:
		if goal.Subject.Type == "Organization" && goal.Purpose == "connected" && len(goal.Relationships) == 0 &&
			controlledReachable(schema, goal.TargetTypes) {
			goal.Answer = LensControlled
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

// ownedTypes lists, from the semantics table, the asset types an owner can
// control: the valid targets of the controlled and table answers.
func ownedTypes(schema SchemaCatalog) []string {
	if schema == nil || meaningsOf(schema) == nil {
		return nil
	}

	var out []string
	for t := range catalogTypes(schema.Relations(), nil) {
		if controlledReachable(schema, []string{t}) {
			out = append(out, t)
		}
	}

	sort.Strings(out)
	return out
}

// tableColumns normalizes a planned column chain. It drops leading columns
// that only repeat the row asset (a URL column in a table of URLs), and
// adds a column for each asset type the question mentions that the chain
// leaves out, before the first controller column so that the controller
// describes it (a question naming IP addresses and hosting providers gets
// the IP address column the provider column needs). Mentions come from the
// vocabulary data; the subject's and row's types and Organization (the
// subject or a controller) are never added.
func tableColumns(goal InvestigationGoal, mentioned []string) []TableColumn {
	cols := append([]TableColumn(nil), goal.Columns...)
	for len(cols) > 1 && len(goal.TargetTypes) == 1 && cols[0].Role == ColumnReached &&
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

	var missing []TableColumn
	for _, t := range mentioned {
		if !present[t] {
			present[t] = true
			missing = append(missing, TableColumn{Type: t, Role: ColumnReached})
		}
	}
	if len(missing) == 0 {
		return cols
	}

	at := len(cols)
	for i, c := range cols {
		if c.Role == ColumnController {
			at = i
			break
		}
	}

	out := append(append(append([]TableColumn(nil), cols[:at]...), missing...), cols[at:]...)
	if len(out) > tableMaxColumns {
		return cols
	}

	return out
}

// mentionedTypes lists, sorted, the catalog asset types the question names
// through the vocabulary. Longer phrases claim their words first, so "IP
// address" names IPAddress and not also Location ("address").
func mentionedTypes(question string, schema SchemaCatalog) []string {
	if schema == nil {
		return nil
	}

	type alias struct{ words, kind string }
	var aliases []alias
	for kind := range catalogTypes(schema.Relations(), nil) {
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
	found := map[string]bool{}
	for _, a := range aliases {
		needle := " " + a.words + " "
		if i := strings.Index(text, needle); i >= 0 {
			found[a.kind] = true
			// Blank the phrase so shorter aliases inside it cannot match.
			text = text[:i+1] + strings.Repeat("#", len(a.words)) + text[i+1+len(a.words):]
		}
	}

	out := make([]string, 0, len(found))
	for t := range found {
		out = append(out, t)
	}

	sort.Strings(out)
	return out
}
