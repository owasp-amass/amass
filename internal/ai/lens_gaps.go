// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

// LensOwnershipGaps finds assets with no documented owner that share
// signals with the subject's controlled assets, scores them, and names the
// one OAM relationship that would record the subject as their owner. It
// proposes; it never writes.
const LensOwnershipGaps = "ownership_gaps"

// Signal kinds, each defined by the attribution of the bridging edge in the
// semantics table.
const (
	// SignalIdentity: an unowned asset shares an attribute value (phone,
	// address, identifier, URL) with a controlled asset, such as another
	// registrant contact with the same phone number.
	SignalIdentity = "identity"
	// SignalHosting: an unowned asset depends on a controlled asset through
	// an infrastructure edge, such as a name resolving into an owned netblock.
	SignalHosting = "hosting"
	// SignalColisting: an unowned asset is listed beside a controlled asset
	// by a shared asset, such as a certificate naming both.
	SignalColisting = "colisting"
)

// Gap bounds.
const (
	gapMaxCandidates = 200
	gapMaxColisted   = 10
	// gapMaxShared skips an attribute value that more assets carry: a
	// provider's or privacy service's phone or address, not an owner's.
	gapMaxShared = 50
	gapMaxGains  = 10
	// gapMaxGainsCounted bounds the gains counted beyond those named.
	gapMaxGainsCounted = 1000
)

// Gap decisions.
const (
	GapPropose = "propose"
	GapReview  = "review"
	GapWeak    = "weak"
)

// Signal IDs from the signal catalog (semantics/ownership_signals.json).
const (
	sigSharedRegistrant = "shared_registrant_details"
	sigHosting          = "hosting_in_footprint"
	sigColisting        = "certificate_colisting"
	sigSelfHostedDNS    = "self_hosted_dns"
)

// GapSignal is one signal linking a candidate to the subject. Signal is its
// ID in the signal catalog, where its rationale is documented.
type GapSignal struct {
	Signal  string        `json:"signal"`
	Kind    string        `json:"kind"`
	Via     string        `json:"via"`
	Witness []WitnessEdge `json:"witness"`
}

// ProposedEdge is an OAM relationship that would record the subject as an
// asset's owner.
type ProposedEdge struct {
	FromID       string `json:"from_id"`
	FromType     string `json:"from_type"`
	From         string `json:"from"`
	Label        string `json:"label"`
	RelationType string `json:"relation_type"`
	ToID         string `json:"to_id"`
	ToType       string `json:"to_type"`
	To           string `json:"to"`
}

// String renders the edge as "ContactRecord x --organization--> Organization y".
func (p ProposedEdge) String() string {
	return fmt.Sprintf("%s %s --%s--> %s %s", p.FromType, p.From, p.Label, p.ToType, p.To)
}

// GapCandidate is an unattributed asset with the signals linking it to the
// subject.
type GapCandidate struct {
	AssetID    string        `json:"asset_id"`
	Type       string        `json:"type"`
	Asset      string        `json:"asset"`
	Signals    []GapSignal   `json:"signals"`
	Score      float64       `json:"score"`
	Decision   string        `json:"decision"`
	Attachment *ProposedEdge `json:"attachment,omitempty"`
	// Alternatives are other relationships that could record the owner; a
	// reviewer chooses, so such a candidate is never proposed outright.
	Alternatives []ProposedEdge `json:"alternatives,omitempty"`
	// Gains are the assets the attachment would bring under the subject.
	Gains []string `json:"gains,omitempty"`
	// GainAssets are the assets behind Gains, in the same order.
	GainAssets []Asset `json:"-"`
}

// OwnershipGapReport is the result of the ownership-gap lens.
type OwnershipGapReport struct {
	Root      Asset `json:"root"`
	Owner     Asset `json:"owner"`
	Footprint int   `json:"footprint"`
	// Domains are the registered domains in the owner's footprint.
	Domains    []string       `json:"domains,omitempty"`
	Candidates []GapCandidate `json:"candidates"`
	Reads      int            `json:"reads"`
	Truncated  bool           `json:"truncated"`
	Reason     string         `json:"reason,omitempty"`
}

// gapSearch holds one ownership-gap run.
type gapSearch struct {
	w       *lensWalker
	owned   map[string]Asset
	owner   Asset
	ownable map[string]bool
	found   map[string]*GapCandidate
	report  *OwnershipGapReport
	// ranges are the address ranges of the owned netblocks: an address in
	// one is owned even when the netblock has more addresses than the lens
	// reads.
	ranges []netip.Prefix
	// domains are the owned registered domains: a name below one is in the
	// subject's namespace even when no stored edge links it.
	domains []string
	// values searches by value for the signals that need it; valueReads
	// counts its searches and tag reads.
	values     ValueSearcher
	valueReads int
}

// searchOwnershipGaps runs the ownership-gap lens from root, an
// Organization or an asset whose documented owner is used.
func searchOwnershipGaps(ctx context.Context, graph Graph, schema SchemaCatalog, root Asset) (OwnershipGapReport, error) {
	report := OwnershipGapReport{Root: root, Candidates: []GapCandidate{}}
	meaning := meaningsOf(schema)
	if schema == nil || meaning == nil {
		return report, errors.New("the ownership-gap lens requires relationship semantics")
	}

	bounded, ok := graph.(BoundedGraph)
	if !ok {
		return report, errors.New("bounded graph reader required")
	}

	counters := &ThirdPartyReport{}
	w := newLensWalker(ctx, graph, bounded, meaning, schema.Relations(), root, counters)
	w.parent, w.via = map[string]string{}, map[string]Relation{}
	owner := root
	roots := []Asset{root}
	if root.Type != "Organization" {
		owners, err := w.owningOrganizations(root)
		if err != nil {
			return report, err
		}
		if len(owners) == 0 {
			report.Reason = "no documented owner for " + assetLabel(root)
			return report, nil
		}

		owner = owners[0]
		roots = append(roots, owner)
	}

	report.Owner = owner
	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return report, err
	}

	report.Footprint = len(owned)
	g := &gapSearch{w: w, owned: owned, owner: owner, found: map[string]*GapCandidate{}, report: &report,
		ownable: map[string]bool{}}
	for _, t := range ownedTypes(schema) {
		g.ownable[t] = true
	}
	for _, a := range owned {
		switch a.Type {
		case "Netblock":
			if p, err := netip.ParsePrefix(contentString(a, "cidr")); err == nil {
				g.ranges = append(g.ranges, p.Masked())
			}
		case "DomainRecord":
			if d := strings.ToLower(strings.TrimSuffix(contentString(a, "domain"), ".")); strings.Contains(d, ".") {
				g.domains = append(g.domains, d)
			}
		}
	}
	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if counters.Reads >= lensMaxReads || len(g.found) >= gapMaxCandidates {
			w.truncate("candidate or read limit")
			break
		}
		if err := g.signalsFrom(owned[id]); err != nil {
			return report, err
		}
	}
	if err := g.valueSignals(order); err != nil {
		return report, err
	}
	for _, c := range g.found {
		if err := g.finish(c); err != nil {
			return report, err
		}
		if c.Decision != "" {
			report.Candidates = append(report.Candidates, *c)
		}
	}

	rank := map[string]int{GapPropose: 0, GapReview: 1, GapWeak: 2}
	sort.Slice(report.Candidates, func(i, j int) bool {
		a, b := report.Candidates[i], report.Candidates[j]
		if rank[a.Decision] != rank[b.Decision] {
			return rank[a.Decision] < rank[b.Decision]
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}

		return a.Asset < b.Asset
	})
	report.Domains = g.domains
	report.Reads, report.Truncated = counters.Reads, counters.Truncated
	if counters.Reason != "" {
		report.Reason = counters.Reason
	}

	return report, nil
}

// pathTo returns the attribution witness from the subject to an owned asset.
func (g *gapSearch) pathTo(id string) []WitnessEdge {
	return pathWitness(g.w.path(id, g.owned))
}

// signalsFrom collects the signals that one controlled asset gives.
func (g *gapSearch) signalsFrom(cur Asset) error {
	steps, err := g.w.steps(cur)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if _, mine := g.owned[s.other.ID]; mine {
			continue
		}

		hop := witnessOf(s.edge, cur, s.other)
		via := s.other.Type + " " + s.edge.Label + " " + cur.Type
		switch {
		case !s.forward && g.reverseDNS(s):
			// Its reverse DNS names one of the subject's hosts.
			if err := g.reverseDNSSignals(cur, s, hop); err != nil {
				return err
			}
		case !s.forward && g.selfHostedDNS(s):
			// Its name or mail servers are the subject's own hosts.
			if rr := rrTypeName(relationRRType(s.edge)); rr != "" {
				via = s.other.Type + " " + rr + " " + cur.Type
			}

			g.add(s.other, sigSelfHostedDNS, via, append(g.pathTo(cur.ID), hop))
		case s.attr == attrInfrastructure && !s.forward:
			// Something outside the footprint depends on a controlled asset.
			g.add(s.other, sigHosting, via, append(g.pathTo(cur.ID), hop))
		case s.attr == "attribute" && s.forward && cur.Type != "Organization":
			if err := g.identity(cur, s, hop); err != nil {
				return err
			}
		case s.attr == attrShared && !s.forward:
			if err := g.colisting(cur, s.other, hop); err != nil {
				return err
			}
		}
	}

	return nil
}

// identity follows an attribute value (a phone, address or identifier) of a
// controlled asset to other assets that carry the same value.
//
// A value that identifies no one gives no signal: a redaction or privacy
// placeholder, or a value carried by more than gapMaxShared assets.
func (g *gapSearch) identity(cur Asset, s step, hop WitnessEdge) error {
	value := s.other
	if isPlaceholder(value) {
		return nil
	}

	steps, err := g.w.steps(value)
	if err != nil {
		return err
	}

	var holders []step
	for _, t := range steps {
		if !t.forward && t.attr == "attribute" {
			holders = append(holders, t)
		}
	}
	if len(holders) > gapMaxShared {
		return nil
	}
	for _, t := range holders {
		other := t.other
		if _, mine := g.owned[other.ID]; mine || other.Type == "Organization" || other.Type == "Person" {
			continue
		}

		witness := append(append(g.pathTo(cur.ID), hop), witnessOf(t.edge, value, other))
		g.add(other, sigSharedRegistrant, cur.Type+" "+s.edge.Label+" "+value.Type, witness)
	}

	return nil
}

// colisting follows a shared asset (a certificate listing a controlled
// name) to the other assets it lists, unless it lists too many to signal
// anything (a provider's multi-tenant certificate).
func (g *gapSearch) colisting(cur, shared Asset, hop WitnessEdge) error {
	steps, err := g.w.steps(shared)
	if err != nil {
		return err
	}

	var listed []step
	for _, t := range steps {
		if t.forward && t.attr == attrShared {
			listed = append(listed, t)
		}
	}
	if len(listed) > gapMaxColisted {
		return nil
	}
	for _, t := range listed {
		if _, mine := g.owned[t.other.ID]; mine {
			continue
		}

		witness := append(append(g.pathTo(cur.ID), hop), witnessOf(t.edge, shared, t.other))
		g.add(t.other, sigColisting, shared.Type+" "+t.edge.Label, witness)
	}

	return nil
}

// add records signal id, found via a route, for candidate a.
func (g *gapSearch) add(a Asset, id, via string, witness []WitnessEdge) {
	if !g.ownable[a.Type] || reverseLookupName(a) {
		return
	}
	if _, mine := g.owned[a.ID]; mine || g.inOwnedRange(a) || g.inOwnedNamespace(a) {
		return
	}

	def, ok := ownershipSignal(id)
	if !ok {
		return
	}

	c, ok := g.found[a.ID]
	if !ok {
		if len(g.found) >= gapMaxCandidates {
			return
		}

		g.w.assets[a.ID] = a
		c = &GapCandidate{AssetID: a.ID, Type: a.Type, Asset: assetLabel(a)}
		g.found[a.ID] = c
	}
	for _, s := range c.Signals {
		if s.Signal == id && s.Via == via {
			return
		}
	}

	c.Signals = append(c.Signals, GapSignal{Signal: id, Kind: def.Kind, Via: via, Witness: witness})
}

// inOwnedRange reports whether a is an address inside an owned netblock.
func (g *gapSearch) inOwnedRange(a Asset) bool {
	if a.Type != "IPAddress" {
		return false
	}

	addr, err := netip.ParseAddr(contentString(a, "address"))
	if err != nil {
		return false
	}
	for _, p := range g.ranges {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// inOwnedNamespace reports whether a is a name, or a URL on a name, at or
// below a registered domain the subject owns.
func (g *gapSearch) inOwnedNamespace(a Asset) bool {
	var host string
	switch a.Type {
	case "FQDN":
		host = assetLabel(a)
	case "URL":
		if u, err := url.Parse(assetLabel(a)); err == nil {
			host = u.Hostname()
		}
	default:
		return false
	}
	for _, d := range g.domains {
		if hostWithin(host, d) {
			return true
		}
	}

	return false
}

// reverseLookupName reports whether a is a reverse-DNS lookup name
// (in-addr.arpa, RFC 1035; ip6.arpa, RFC 3596): DNS mechanics for an
// address, not an asset anyone owns.
func reverseLookupName(a Asset) bool {
	if a.Type != "FQDN" {
		return false
	}

	name := strings.ToLower(strings.TrimSuffix(assetLabel(a), "."))
	return strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa")
}

// finish drops candidates another organization controls, then scores the
// rest and finds their attachment edge and gains.
func (g *gapSearch) finish(c *GapCandidate) error {
	a := g.w.assets[c.AssetID]
	ctl, err := g.w.controllerOf(a, g.owned)
	if err != nil {
		return err
	}
	if ctl.own || len(ctl.orgs) > 0 {
		// Documented as controlled (by the subject or another organization):
		// not a gap. Other controllers are partner signals, not proposals.
		return nil
	}

	edges, gains, err := g.attachment(a, ctl)
	if err != nil {
		return err
	}
	if len(edges) > 0 {
		c.Attachment, c.Alternatives = &edges[0], edges[1:]
	}

	// The answer names the first gains and counts the rest; scope widening
	// uses the named ones.
	more := 0
	if len(gains) > gapMaxGains {
		more, gains = len(gains)-gapMaxGains, gains[:gapMaxGains]
	}

	c.GainAssets = gains
	for _, v := range gains {
		c.Gains = append(c.Gains, v.Type+" "+assetLabel(v))
	}
	if more > 0 {
		c.Gains = append(c.Gains, fmt.Sprintf("and %d more", more))
	}

	if err := g.contextSignals(a, c); err != nil {
		return err
	}

	// Only one unambiguous relationship can be proposed outright.
	c.Score, c.Decision = scoreGap(c.Signals, len(edges) == 1)
	return nil
}

// scoreGap rates a candidate's signals by their catalog strength and
// weight. A strong signal (shared registrant details, a shared verification
// token) points to one owner; a supporting one (hosting, co-listing) is
// consistent with many; a tiebreaker (a name token, a TLS fingerprint)
// only ranks and never corroborates a proposal; a negative one (a parked
// page) counts against
// ownership and keeps the candidate from being proposed. Each signal counts
// at most twice toward the score, which ranks candidates and is not a
// probability.
func scoreGap(signals []GapSignal, attachable bool) (float64, string) {
	return scoreSignals(signals, attachable, ownershipSignal)
}

// scoreSignals applies the shared decision rules to signals defined by
// lookup.
func scoreSignals(signals []GapSignal, attachable bool, lookup func(string) (OwnershipSignal, bool)) (float64, string) {
	count := map[string]int{}
	corroborating := map[string]bool{}
	strong := 0
	negative := false
	score := 0.0
	for _, s := range signals {
		def, ok := lookup(s.Signal)
		if !ok {
			continue
		}
		if def.Strength == StrengthNegative {
			negative = true
			score -= def.Weight
			continue
		}

		count[s.Signal]++
		if !def.Tiebreaker {
			corroborating[s.Signal] = true
		}
		if def.Strength == StrengthStrong {
			strong++
		}
		if count[s.Signal] <= 2 {
			score += def.Weight
		}
	}

	// A strong signal is corroborated by a different signal that is not a
	// tiebreaker.
	score = math.Max(0, math.Min(1, score))
	switch {
	case attachable && !negative && (strong >= 2 || (strong >= 1 && len(corroborating) >= 2)):
		return score, GapPropose
	case strong >= 1 || len(count) >= 2:
		return score, GapReview
	default:
		return score, GapWeak
	}
}

// attachment finds, along the candidate's ownership chain, the closest
// asset that an OAM relationship can attribute to an Organization (a
// contact record's organization, an organization's website) and that has
// no such relationship yet, and the assets that edge would bring under the
// subject.
func (g *gapSearch) attachment(a Asset, ctl controller) ([]ProposedEdge, []Asset, error) {
	for _, v := range ctl.visited {
		edges := g.attachEdges(v)
		if len(edges) == 0 {
			continue
		}

		gains, err := g.gains(v)
		return edges, gains, err
	}

	return nil, nil, nil
}

// attachEdges returns the catalog relationships that would attribute v to
// the subject, sorted by label.
func (g *gapSearch) attachEdges(v Asset) []ProposedEdge {
	var out []ProposedEdge
	for _, r := range g.w.relations {
		m, ok := g.w.meaning(r.SourceType, r.Label, r.RelationType, r.DestinationType)
		if !ok {
			continue
		}
		switch {
		case r.SourceType == v.Type && r.DestinationType == "Organization" &&
			(m.Attribution == attrSameSubject || m.Attribution == attrController):
			out = append(out, ProposedEdge{FromID: v.ID, FromType: v.Type, From: assetLabel(v), Label: r.Label,
				RelationType: r.RelationType, ToID: g.owner.ID, ToType: "Organization", To: assetLabel(g.owner)})
		case r.SourceType == "Organization" && r.DestinationType == v.Type && m.Attribution == attrControls &&
			v.Type != "Organization":
			out = append(out, ProposedEdge{FromID: g.owner.ID, FromType: "Organization", From: assetLabel(g.owner),
				Label: r.Label, RelationType: r.RelationType, ToID: v.ID, ToType: v.Type, To: assetLabel(v)})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// gains lists the assets that attributing v would bring under the subject.
func (g *gapSearch) gains(v Asset) ([]Asset, error) {
	seen := map[string]bool{v.ID: true}
	queue := []Asset{v}
	var out []Asset
	for len(queue) > 0 && len(out) < gapMaxGainsCounted {
		cur := queue[0]
		queue = queue[1:]
		steps, err := g.w.steps(cur)
		if err != nil {
			return nil, err
		}
		for _, s := range steps {
			if seen[s.other.ID] || !footprintPass(s) || s.other.Type == "Organization" || s.other.Type == "Person" {
				continue
			}

			seen[s.other.ID] = true
			out = append(out, s.other)
			queue = append(queue, s.other)
			if len(out) >= gapMaxGainsCounted {
				break
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Type+" "+assetLabel(out[i]) < out[j].Type+" "+assetLabel(out[j])
	})
	return out, nil
}

// gapAnswer renders an OwnershipGapReport as plain text.
func gapAnswer(r OwnershipGapReport) string {
	subject := assetLabel(r.Root) + " (" + r.Root.Type + ")"
	if r.Owner.ID == "" {
		return "No documented owner for " + subject + ", so there is no footprint to compare unattributed assets with."
	}

	var b strings.Builder
	if len(r.Candidates) == 0 {
		fmt.Fprintf(&b, "No unattributed assets share ownership signals with the %d assets controlled by %s.",
			r.Footprint, assetLabel(r.Owner))
		if r.Truncated && r.Reason != "" {
			fmt.Fprintf(&b, " Results are partial (%s).", r.Reason)
		}

		return b.String()
	}

	fmt.Fprintf(&b, "%d unattributed asset(s) share signals with the %d assets controlled by %s:\n", len(r.Candidates),
		r.Footprint, assetLabel(r.Owner))
	for _, c := range r.Candidates {
		kinds := map[string]bool{}
		var names []string
		for _, s := range c.Signals {
			if !kinds[s.Kind] {
				kinds[s.Kind] = true
				names = append(names, s.Kind)
			}
		}

		fmt.Fprintf(&b, "  [%s %.2f] %s %s: %s", c.Decision, c.Score, c.Type, c.Asset, strings.Join(names, ", "))
		if c.Attachment != nil {
			fmt.Fprintf(&b, "; would record %s", c.Attachment)
			for _, alt := range c.Alternatives {
				fmt.Fprintf(&b, " or %s", alt.Label)
			}
		} else {
			b.WriteString("; no OAM relationship can record its owner without new records")
		}
		if len(c.Gains) > 0 {
			fmt.Fprintf(&b, "; brings %s", strings.Join(c.Gains, ", "))
		}

		b.WriteString("\n")
	}

	b.WriteString("These are proposals from stored signals, not documented ownership. Nothing has been written.")
	if r.Truncated {
		b.WriteString(" Results are partial (" + r.Reason + ").")
	}

	return b.String()
}

// gapLens answers an ownership-gap lens query from root.
func (a Agent) gapLens(ctx context.Context, root Asset, out Investigation) (Investigation, error) {
	started := time.Now()
	report, err := searchOwnershipGaps(ctx, a.Runner.Graph, a.Runner.Catalog, root)
	out.recordTrace(started, InvestigationTraceEvent{Stage: "ownership_gap_lens", OutputPaths: len(report.Candidates),
		GraphNodes: report.Footprint, Incomplete: err != nil || report.Truncated, Detail: report.Reason})
	if err != nil {
		out.Incomplete = true
		return out, err
	}

	out.ToolCalls++
	out.GapReport = &report
	out.Incomplete = report.Truncated
	out.Answer = gapAnswer(report)
	return out, nil
}
