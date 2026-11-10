// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
)

// The ownership signal catalog defines every signal the ownership-gap lens
// and automatic attribution use, with the rationale shown to users.
//
//go:embed semantics/ownership_signals.json
var ownershipSignalsJSON []byte

// Signal strengths.
const (
	StrengthStrong     = "strong"
	StrengthSupporting = "supporting"
	// StrengthNegative counts against ownership: it lowers the score and
	// keeps a candidate from being proposed for an automatic write.
	StrengthNegative = "negative"
)

// Signal matchers: how a signal is found in the graph.
const (
	matchSharedAttribute   = "shared_attribute"
	matchInfrastructure    = "infrastructure_into_footprint"
	matchColisting         = "colisting"
	matchTXTToken          = "txt_token"
	matchCertificateField  = "shared_certificate_field"
	matchDNSIntoFootprint  = "dns_into_footprint"
	matchTXTReference      = "txt_reference"
	matchHTTPRedirect      = "http_redirect"
	matchReverseDNS        = "reverse_dns"
	matchNameserverSet     = "nameserver_set"
	matchFingerprint       = "service_fingerprint"
	matchNameToken         = "name_token"
	matchParkedPage        = "parked_page"
	signalCatalogMaxWeight = 1
)

var signalMatchers = map[string]bool{matchSharedAttribute: true, matchInfrastructure: true, matchColisting: true,
	matchTXTToken: true, matchCertificateField: true, matchDNSIntoFootprint: true, matchTXTReference: true,
	matchHTTPRedirect: true, matchReverseDNS: true, matchNameserverSet: true, matchFingerprint: true,
	matchNameToken: true, matchParkedPage: true}

// SignalParams configures a signal's matcher.
type SignalParams struct {
	TXTPrefixes   []string `json:"txt_prefixes,omitempty"`
	Attribute     string   `json:"attribute,omitempty"`
	PublicIssuers []string `json:"public_issuers,omitempty"`
	RRTypes       []int    `json:"rr_types,omitempty"`
	Labels        []string `json:"labels,omitempty"`
	Headers       []string `json:"headers,omitempty"`
	MinServers    int      `json:"min_servers,omitempty"`
	Property      string   `json:"property,omitempty"`
	MinLength     int      `json:"min_length,omitempty"`
	StopWords     []string `json:"stop_words,omitempty"`
	Phrases       []string `json:"phrases,omitempty"`
}

// OwnershipSignal is one kind of ownership evidence and why it counts.
type OwnershipSignal struct {
	ID       string  `json:"id"`
	Title    string  `json:"title"`
	Kind     string  `json:"kind"`
	Strength string  `json:"strength"`
	Weight   float64 `json:"weight"`
	// Tiebreaker marks weak evidence that ranks candidates but never
	// corroborates a strong signal into a proposal.
	Tiebreaker         bool         `json:"tiebreaker,omitempty"`
	Matcher            string       `json:"matcher"`
	Params             SignalParams `json:"params,omitzero"`
	Finds              string       `json:"finds"`
	Rationale          string       `json:"rationale"`
	Guards             []string     `json:"guards"`
	CounterIndications []string     `json:"counter_indications"`
}

type signalCatalog struct {
	License string            `json:"_license"`
	About   string            `json:"_about"`
	Signals []OwnershipSignal `json:"signals"`
}

var loadSignalCatalog = sync.OnceValues(func() (signalCatalog, error) {
	var c signalCatalog
	if err := decodeStrict(ownershipSignalsJSON, &c); err != nil {
		return c, fmt.Errorf("ownership_signals.json: %w", err)
	}

	return c, validateSignals(c.Signals)
})

func validateSignals(signals []OwnershipSignal) error {
	seen := map[string]bool{}
	for _, s := range signals {
		switch {
		case s.ID == "" || seen[s.ID]:
			return fmt.Errorf("signal %q: missing or repeated id", s.ID)
		case s.Title == "" || s.Kind == "" || s.Finds == "" || s.Rationale == "":
			return fmt.Errorf("signal %s: title, kind, finds and rationale are required", s.ID)
		case s.Strength != StrengthStrong && s.Strength != StrengthSupporting && s.Strength != StrengthNegative:
			return fmt.Errorf("signal %s: strength must be strong, supporting or negative", s.ID)
		case s.Weight <= 0 || s.Weight > signalCatalogMaxWeight:
			return fmt.Errorf("signal %s: weight must be in (0, 1]", s.ID)
		case !signalMatchers[s.Matcher]:
			return fmt.Errorf("signal %s: unknown matcher %q", s.ID, s.Matcher)
		case s.Matcher == matchTXTToken && len(s.Params.TXTPrefixes) == 0:
			return fmt.Errorf("signal %s: txt_prefixes required", s.ID)
		case s.Matcher == matchCertificateField && s.Params.Attribute == "":
			return fmt.Errorf("signal %s: attribute required", s.ID)
		case s.Matcher == matchHTTPRedirect && len(s.Params.Headers) == 0:
			return fmt.Errorf("signal %s: headers required", s.ID)
		case (s.Matcher == matchReverseDNS || s.Matcher == matchDNSIntoFootprint) && len(s.Params.Labels) == 0:
			return fmt.Errorf("signal %s: labels required", s.ID)
		case s.Matcher == matchNameserverSet && s.Params.MinServers < 2:
			return fmt.Errorf("signal %s: min_servers must be at least 2", s.ID)
		case s.Matcher == matchFingerprint && s.Params.Property == "":
			return fmt.Errorf("signal %s: property required", s.ID)
		case s.Matcher == matchNameToken && s.Params.MinLength < 3:
			return fmt.Errorf("signal %s: min_length must be at least 3", s.ID)
		case s.Matcher == matchParkedPage && len(s.Params.Phrases) == 0:
			return fmt.Errorf("signal %s: phrases required", s.ID)
		case (s.Strength == StrengthNegative) != (s.Matcher == matchParkedPage):
			return fmt.Errorf("signal %s: only the parked_page matcher is negative", s.ID)
		}

		seen[s.ID] = true
	}

	return nil
}

// OwnershipSignals returns the signal catalog.
func OwnershipSignals() []OwnershipSignal {
	c, err := loadSignalCatalog()
	if err != nil {
		panic(err)
	}

	return c.Signals
}

// ownershipSignal returns the catalog entry for id.
func ownershipSignal(id string) (OwnershipSignal, bool) {
	for _, s := range OwnershipSignals() {
		if s.ID == id {
			return s, true
		}
	}

	return OwnershipSignal{}, false
}

// signalsByMatcher returns the catalog entries a matcher produces.
func signalsByMatcher(matcher string) []OwnershipSignal {
	var out []OwnershipSignal
	for _, s := range OwnershipSignals() {
		if s.Matcher == matcher {
			out = append(out, s)
		}
	}

	return out
}

// SignalsMarkdown renders the catalog as the user documentation in
// docs/ai/SIGNALS.md.
func SignalsMarkdown() string {
	c, err := loadSignalCatalog()
	if err != nil {
		panic(err)
	}

	var b strings.Builder
	b.WriteString("# Ownership signals\n\n")
	b.WriteString("<!-- Generated from internal/ai/semantics/ownership_signals.json by `amass ai signals -format markdown`." +
		" Edit that file, not this one. -->\n\n")
	b.WriteString("Amass proposes that an organization owns an asset it has not been attributed to only from stored " +
		"evidence. Each kind of evidence is a signal, listed here with why it counts, what stops it from " +
		"misfiring, and when it can still mislead. The same text is shown by `amass ai signals`.\n\n")
	b.WriteString("## How signals decide\n\n")
	b.WriteString("- A candidate with two strong signals, or one strong signal and a different second signal, is " +
		"**proposed** when exactly one OAM relationship can record the owner. During enumeration a proposed " +
		"candidate is written automatically (with the `amass-ai` source) unless attribution is set to `journal` " +
		"or `off`.\n")
	b.WriteString("- One strong signal, or two signals of any strength, **needs review**: it waits in the review " +
		"journal for a person.\n")
	b.WriteString("- Anything less is **weak** and only reported.\n")
	b.WriteString("- A **tiebreaker** (marked below) ranks candidates and can send one to review, but never counts " +
		"as the second signal that lets a strong signal propose.\n")
	b.WriteString("- A **negative** signal lowers the score and keeps a candidate from being proposed: at most it " +
		"needs review.\n")
	b.WriteString("- Weights rank candidates; they are not probabilities. Once enough proposals have been reviewed, " +
		"`amass ai train-attribution` learns the weights from those decisions and the trained model decides " +
		"instead.\n\n")
	b.WriteString("| Signal | Strength | Kind | Weight |\n| --- | --- | --- | --- |\n")
	for _, s := range c.Signals {
		strength := s.Strength
		if s.Tiebreaker {
			strength += " (tiebreaker)"
		}

		fmt.Fprintf(&b, "| [%s](#%s) | %s | %s | %.2f |\n", s.Title, s.ID, strength, s.Kind, s.Weight)
	}
	for _, s := range c.Signals {
		fmt.Fprintf(&b, "\n<a id=\"%s\"></a>\n## %s\n\n", s.ID, s.Title)
		tie := ""
		if s.Tiebreaker {
			tie = " Tiebreaker."
		}

		fmt.Fprintf(&b, "`%s`: %s %s signal, weight %.2f.%s\n\n", s.ID, s.Strength, s.Kind, s.Weight, tie)
		fmt.Fprintf(&b, "**Finds:** %s\n\n**Why it counts:** %s\n", s.Finds, s.Rationale)
		writeList(&b, "Guards", s.Guards)
		writeList(&b, "Can still mislead when", s.CounterIndications)
		if len(s.Params.TXTPrefixes) > 0 {
			fmt.Fprintf(&b, "\n**Verification prefixes:** `%s`\n", strings.Join(s.Params.TXTPrefixes, "`, `"))
		}
		if len(s.Params.Phrases) > 0 {
			fmt.Fprintf(&b, "\n**Page phrases:** `%s`\n", strings.Join(s.Params.Phrases, "`, `"))
		}
	}

	return b.String()
}

func writeList(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}

	fmt.Fprintf(b, "\n**%s:**\n\n", title)
	for _, i := range items {
		fmt.Fprintf(b, "- %s\n", i)
	}
}

// SignalsText renders the catalog for a terminal.
func SignalsText() string {
	var b strings.Builder
	for i, s := range OwnershipSignals() {
		if i > 0 {
			b.WriteString("\n")
		}

		tie := ""
		if s.Tiebreaker {
			tie = ", tiebreaker"
		}

		fmt.Fprintf(&b, "%s (%s): %s %s signal, weight %.2f%s\n", s.Title, s.ID, s.Strength, s.Kind, s.Weight, tie)
		fmt.Fprintf(&b, "  Finds: %s\n  Why it counts: %s\n", s.Finds, s.Rationale)
		for _, g := range s.Guards {
			fmt.Fprintf(&b, "  Guard: %s\n", g)
		}
		for _, c := range s.CounterIndications {
			fmt.Fprintf(&b, "  Can mislead: %s\n", c)
		}
	}

	return b.String()
}
