// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensGroupFunding asks for the funding received across a whole corporate
// group: the funding of the subject organization and of every parent,
// subsidiary and unit in its group, merged, with which group organization
// received each round. One institution's funding is often split across org
// records that different funders name differently (a state university system
// and one of its campuses, say), so a group rollup shows the whole picture.
// The answer is built in Go from stored records; nothing is written.
const LensGroupFunding = "group_funding"

// Group funding rollup bounds.
const (
	// groupFundingMaxScopes bounds the organizations scanned.
	groupFundingMaxScopes = 50
	// groupFundingMinReads is the smallest read budget one scope is given.
	groupFundingMinReads = 1000
)

var groupFundingLens = SubjectLens{
	Name:    LensGroupFunding,
	Command: "group-funding",
	Description: "Show funding across an organization's corporate group: rounds, amounts, dates and investors " +
		"for it and each parent, subsidiary and unit, merged, noting which one received each. From a domain, " +
		"its main organization's group. Read-only.",
	Examples: []string{
		"What funding has <organization>'s corporate group raised?",
		"How much have <organization> and its subsidiaries received, and from whom?",
	},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindGroupFunding(ctx, g, schema, root, opts.Limits)
	},
}

// GroupFundingRound is one funding round received by a group organization.
type GroupFundingRound struct {
	FundingRound
	// Recipient is the group organization that received the round.
	Recipient   string `json:"recipient"`
	RecipientID string `json:"recipient_id,omitempty"`
}

// GroupFundingRecipient summarizes one group organization's funding.
type GroupFundingRecipient struct {
	Name     string  `json:"name"`
	AssetID  string  `json:"asset_id"`
	Rounds   int     `json:"rounds"`
	Total    float64 `json:"total,omitempty"`
	Currency string  `json:"currency,omitempty"`
}

// GroupFundingReport is the result of the group funding rollup.
type GroupFundingReport struct {
	lensBase
	Group      GroupReport             `json:"group"`
	Rounds     []GroupFundingRound     `json:"rounds"`
	Recipients []GroupFundingRecipient `json:"recipients,omitempty"`
	// Investors is the union of investors across the group, sorted.
	Investors []string `json:"investors,omitempty"`
	// Total is the sum of round amounts and Currency their shared currency,
	// set only when every round with an amount uses the same one.
	Total    float64 `json:"total,omitempty"`
	Currency string  `json:"currency,omitempty"`
	// Skipped counts group organizations not scanned because of the scope or
	// read bounds.
	Skipped int `json:"skipped,omitempty"`
}

// FindGroupFunding runs the funding lens for each organization of a corporate
// group (from the group of root's main organization when root is a domain) and
// merges the rounds, recording which organization received each. The read
// budget in limits is shared across the group. It reads only.
func FindGroupFunding(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (GroupFundingReport, error) {
	var out GroupFundingReport
	if err := limits.Validate(); err != nil {
		return out, err
	}

	group, err := FindCorporateGroup(ctx, g, root)
	if err != nil {
		return out, err
	}
	out.Root = root
	out.Group = group
	out.Reads = group.Reads
	if group.Truncated {
		out.Truncated, out.Reason = true, "org-group: "+group.Reason
	}

	// Process members shallowest first. A member's funding scope also covers
	// the organizations above it (its owners), so attributing each round to
	// the first member that surfaces it, top-down, credits it to the
	// organization that actually received it rather than a descendant.
	members := append([]GroupMember(nil), group.Members...)
	sort.SliceStable(members, func(i, j int) bool { return members[i].Depth < members[j].Depth })
	scopes := make([]graph.Asset, 0, len(members))
	for _, m := range members {
		scopes = append(scopes, m.Organization)
	}
	if len(scopes) > groupFundingMaxScopes {
		out.Skipped = len(scopes) - groupFundingMaxScopes
		scopes = scopes[:groupFundingMaxScopes]
		out.truncate(fmt.Sprintf("more than %d organizations in the group", groupFundingMaxScopes))
	}

	seen := map[string]bool{} // round id already attributed to a group organization
	investors := map[string]bool{}
	budget := limits.reads()
	for i, scope := range scopes {
		if err := ctx.Err(); err != nil {
			return out, err
		}

		remaining := budget - out.Reads
		if remaining < groupFundingMinReads {
			out.Skipped += len(scopes) - i
			out.truncate("database read limit")
			break
		}
		share := max(remaining/(len(scopes)-i), groupFundingMinReads)

		r, err := FindFunding(ctx, g, schema, scope,
			LensLimits{MaxAssets: limits.MaxAssets, MaxReads: min(share, remaining)})
		if err != nil {
			return out, fmt.Errorf("funding of %s: %w", graph.AssetLabel(scope), err)
		}
		out.Reads += r.Reads
		if r.Truncated && !out.Truncated {
			out.truncate("funding of " + graph.AssetLabel(scope) + ": " + r.Reason)
		}

		name := graph.AssetLabel(scope)
		rec := GroupFundingRecipient{Name: name, AssetID: scope.ID}
		recCur := ""
		recMixed := false
		for _, rd := range r.Rounds {
			if seen[rd.Round] {
				continue
			}
			seen[rd.Round] = true
			out.Rounds = append(out.Rounds, GroupFundingRound{FundingRound: rd, Recipient: name, RecipientID: scope.ID})
			rec.Rounds++
			if rd.Amount > 0 {
				switch {
				case recCur == "":
					recCur = rd.Currency
				case recCur != rd.Currency:
					recMixed = true
				}
				rec.Total += rd.Amount
			}
			for _, inv := range rd.Investors {
				investors[inv] = true
			}
		}
		if rec.Rounds > 0 {
			if recMixed {
				rec.Total = 0 // mixed currencies; leave the recipient total unset
			} else {
				rec.Currency = recCur
			}
			out.Recipients = append(out.Recipients, rec)
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
	out.Total, out.Currency = out.groupTotal()
	return out, nil
}

// truncate records the first reason the rollup was cut short.
func (r *GroupFundingReport) truncate(reason string) {
	if !r.Truncated {
		r.Truncated, r.Reason = true, reason
	}
}

// groupTotal sums the round amounts when every round with an amount shares a
// currency, and returns 0 otherwise.
func (r GroupFundingReport) groupTotal() (float64, string) {
	var sum float64
	var currency string
	for _, rd := range r.Rounds {
		if rd.Amount == 0 {
			continue
		}
		switch {
		case currency == "":
			currency = rd.Currency
		case currency != rd.Currency:
			return 0, "" // mixed currencies
		}
		sum += rd.Amount
	}
	return sum, currency
}

// Text implements Report.
func (r GroupFundingReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)

	fmt.Fprintf(&b, "Funding across the corporate group of %s: %d round(s), %d investor(s) "+
		"across %d organization(s) (%d reads).\n",
		subject, len(r.Rounds), len(r.Investors), len(r.Recipients), r.Reads)
	if r.Total > 0 {
		fmt.Fprintf(&b, "Total raised: %s.\n", money(r.Total, r.Currency))
	}

	if len(r.Rounds) == 0 {
		b.WriteString("\nNo funding record is stored for the group.\n")
		return b.String()
	}

	if len(r.Recipients) > 0 {
		b.WriteString("\nBy organization:\n")
		for _, rec := range r.Recipients {
			fmt.Fprintf(&b, "  %s: %d round(s)", rec.Name, rec.Rounds)
			if rec.Total > 0 {
				fmt.Fprintf(&b, ", %s", money(rec.Total, rec.Currency))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\nRounds:\n")
	for _, rd := range r.Rounds {
		fmt.Fprintf(&b, "  %s", rd.Round)
		if rd.Date != "" {
			fmt.Fprintf(&b, " (%s)", rd.Date)
		}
		if rd.Amount > 0 {
			fmt.Fprintf(&b, ": %s", money(rd.Amount, rd.Currency))
		}
		fmt.Fprintf(&b, " — %s", rd.Recipient)
		if len(rd.Investors) > 0 {
			fmt.Fprintf(&b, " — investors: %s", strings.Join(rd.Investors, ", "))
		}
		b.WriteString("\n")
	}

	b.WriteString("\nThese are stored funding records, not a live feed." + r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r GroupFundingReport) Facts() []string {
	out := make([]string, 0, len(r.Rounds)+len(r.Investors))
	for _, rd := range r.Rounds {
		out = append(out, "funding round "+rd.Round)
	}
	for _, n := range r.Investors {
		out = append(out, "investor "+n)
	}
	return out
}
