// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensFunding asks for the funding a domain or organization has received — the
// rounds, their amounts and dates, and the investors behind them — from stored
// funding records (FundsTransfer assets). Investors are a strong signal of an
// organization's partners and backers. The answer is built in Go from stored
// records; nothing is written.
const LensFunding = "funding"

var fundingLens = SubjectLens{
	Name:    LensFunding,
	Command: "funding",
	Description: "Show the funding a domain or organization has received: the rounds, their amounts and dates, " +
		"and the investors behind them. Read-only",
	Examples: []string{"What funding has <organization> raised?",
		"Who are <organization>'s investors?",
		"When did <domain>'s company last raise money?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindFunding(ctx, g, schema, root, opts.Limits)
	},
}

// FundingRound is one funding event the subject received.
type FundingRound struct {
	Round     string   `json:"round"`
	Amount    float64  `json:"amount,omitempty"`
	Currency  string   `json:"currency,omitempty"`
	Date      string   `json:"date,omitempty"`
	Investors []string `json:"investors,omitempty"`
}

// FundingReport is the result of the funding lens.
type FundingReport struct {
	lensBase
	Rounds []FundingRound `json:"rounds"`
	// Investors is the union of investors across all rounds, sorted.
	Investors []string `json:"investors,omitempty"`
	// Total is the sum of round amounts and Currency their shared currency,
	// set only when every round with an amount uses the same one.
	Total    float64 `json:"total,omitempty"`
	Currency string  `json:"currency,omitempty"`
}

// FindFunding lists the funding rounds a domain or organization received and
// the investors behind them, from stored FundsTransfer records. It reads only.
func FindFunding(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (FundingReport, error) {
	g = graph.Cached(g)
	var out FundingReport
	s, err := newScope(ctx, g, schema, root, limits, LensFunding)
	if err != nil {
		return out, err
	}

	subjects := append([]graph.Asset(nil), s.owners...)
	if root.Type == "Organization" {
		subjects = append(subjects, root)
	}

	investors := map[string]bool{}
	seenRound := map[string]bool{}
	for _, org := range subjects {
		if s.spent() {
			break
		}
		accounts, err := s.forwardOfType(org, "Account")
		if err != nil {
			return out, err
		}
		for _, acct := range accounts {
			round, err := s.fundingRounds(acct, seenRound, investors)
			if err != nil {
				return out, err
			}
			out.Rounds = append(out.Rounds, round...)
		}
	}

	for name := range investors {
		out.Investors = append(out.Investors, name)
	}
	sort.Strings(out.Investors)
	sort.Slice(out.Rounds, func(i, j int) bool {
		if out.Rounds[i].Date != out.Rounds[j].Date {
			return out.Rounds[i].Date > out.Rounds[j].Date // most recent first
		}
		return out.Rounds[i].Round < out.Rounds[j].Round
	})
	out.total()
	out.lensBase = s.base()
	return out, nil
}

// fundingRounds returns the funding rounds received into one of the subject's
// accounts, with the investors behind each. The recipient of a round is the
// account reached here; the round's other account is the senders' (the
// investors').
func (s *scope) fundingRounds(acct graph.Asset, seen map[string]bool, investors map[string]bool) ([]FundingRound, error) {
	steps, err := s.w.steps(acct)
	if err != nil {
		return nil, err
	}

	var out []FundingRound
	for _, st := range steps {
		// A funding record naming this account as recipient points at it.
		if st.forward || st.other.Type != "FundsTransfer" {
			continue
		}
		ft := st.other
		if seen[ft.ID] {
			continue
		}
		seen[ft.ID] = true

		round := FundingRound{
			Round:    graph.AssetLabel(ft),
			Currency: graph.ContentString(ft, "currency"),
			Date:     graph.ContentString(ft, "exchange_date"),
		}
		round.Amount = contentFloat(ft, "amount")

		names, err := s.roundInvestors(ft, acct.ID)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			graph.AddUnique(&round.Investors, n)
			investors[n] = true
		}
		sort.Strings(round.Investors)
		out = append(out, round)
	}
	return out, nil
}

// roundInvestors names the investors behind a funding record: the
// organizations holding the sender account (every account the record points at
// other than the recipient), and any organization named directly on the
// record.
func (s *scope) roundInvestors(ft graph.Asset, recipientID string) ([]string, error) {
	steps, err := s.w.steps(ft)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, st := range steps {
		if !st.forward {
			continue
		}
		switch st.other.Type {
		case "Organization":
			// A party named directly on the transfer (third_party investor).
			graph.AddUnique(&names, graph.AssetLabel(st.other))
		case "Account":
			if st.other.ID == recipientID {
				continue // the recipient is the subject, not an investor
			}
			orgs, err := s.backOrganizations(st.other)
			if err != nil {
				return nil, err
			}
			for _, o := range orgs {
				graph.AddUnique(&names, o)
			}
		}
	}
	return names, nil
}

// backOrganizations names the organizations that hold an account (reached by
// an incoming account relationship).
func (s *scope) backOrganizations(acct graph.Asset) ([]string, error) {
	steps, err := s.w.steps(acct)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, st := range steps {
		if !st.forward && st.other.Type == "Organization" {
			graph.AddUnique(&names, graph.AssetLabel(st.other))
		}
	}
	return names, nil
}

// forwardOfType returns the assets of a type reached by a forward edge from a.
func (s *scope) forwardOfType(a graph.Asset, typ string) ([]graph.Asset, error) {
	steps, err := s.w.steps(a)
	if err != nil {
		return nil, err
	}

	var out []graph.Asset
	for _, st := range steps {
		if st.forward && st.other.Type == typ {
			out = append(out, st.other)
		}
	}
	return out, nil
}

// total sums the round amounts when they share a currency.
func (r *FundingReport) total() {
	var sum float64
	currency := ""
	for _, rd := range r.Rounds {
		if rd.Amount == 0 {
			continue
		}
		if currency == "" {
			currency = rd.Currency
		} else if currency != rd.Currency {
			return // mixed currencies; leave Total unset
		}
		sum += rd.Amount
	}
	r.Total, r.Currency = sum, currency
}

// Text implements Report.
func (r FundingReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Funding of %s: %d round(s), %d investor(s) (%d reads).\n",
		subject, len(r.Rounds), len(r.Investors), r.Reads)
	if r.Total > 0 {
		fmt.Fprintf(&b, "Total raised: %s.\n", money(r.Total, r.Currency))
	}

	if len(r.Rounds) == 0 {
		b.WriteString("\nNo funding record is stored.\n")
		return b.String()
	}

	b.WriteString("\n")
	for _, rd := range r.Rounds {
		fmt.Fprintf(&b, "  %s", rd.Round)
		if rd.Date != "" {
			fmt.Fprintf(&b, " (%s)", rd.Date)
		}
		if rd.Amount > 0 {
			fmt.Fprintf(&b, ": %s", money(rd.Amount, rd.Currency))
		}
		if len(rd.Investors) > 0 {
			fmt.Fprintf(&b, " — investors: %s", strings.Join(rd.Investors, ", "))
		}
		b.WriteString("\n")
	}

	b.WriteString("\nThese are stored funding records, not a live feed." + r.partialNote() + "\n")
	return b.String()
}

// contentFloat reads a numeric field from an asset's content. It marshals the
// content to JSON first, as graph.ContentString does, so it works whether the
// content is a typed asset struct (for example *financial.FundsTransfer, whose
// Amount field is otherwise invisible to a map type assertion) or a map.
func contentFloat(a graph.Asset, key string) float64 {
	data, err := json.Marshal(a.Content)
	if err != nil {
		return 0
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return 0
	}
	raw, ok := fields[key]
	if !ok {
		return 0
	}
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return f
	}
	return 0
}

// money formats an amount with its currency.
func money(amount float64, currency string) string {
	if currency == "" {
		currency = "USD"
	}
	return fmt.Sprintf("%s %s", humanAmount(amount), currency)
}

// humanAmount renders a large amount compactly (1.2M, 3.5B).
func humanAmount(a float64) string {
	switch {
	case a >= 1e9:
		return fmt.Sprintf("%.1fB", a/1e9)
	case a >= 1e6:
		return fmt.Sprintf("%.1fM", a/1e6)
	case a >= 1e3:
		return fmt.Sprintf("%.0fK", a/1e3)
	default:
		return fmt.Sprintf("%.0f", a)
	}
}

// Facts implements Report.
func (r FundingReport) Facts() []string {
	out := make([]string, 0, len(r.Rounds)+len(r.Investors))
	for _, rd := range r.Rounds {
		out = append(out, "funding round "+rd.Round)
	}
	for _, n := range r.Investors {
		out = append(out, "investor "+n)
	}
	return out
}
