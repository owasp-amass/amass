// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// A correlator is a Goal-2 detector that concludes two assets stand in some OAM
// relationship — an organizational unit of a parent, the owner of a related
// domain, a vendor, and so on — from evidence already in the Asset Database. It
// never writes: it returns candidates that become review-gated, reversible
// proposals (ai-design-principles.md, principles 9 & 10). The generic shapes
// here let a new correlation be a detector plus signal data rather than new
// review and CLI plumbing: each one reuses review.RelationProposals / ApplyRelation
// and the `amass review <kind>` dispatch.

// RelationCandidate is one proposed relationship From --Label--> To that a
// correlator found, with the signals and evidence that justify it. From and To
// name existing assets by their entity IDs; Label is the OAM relation to create.
type RelationCandidate struct {
	FromID string `json:"from_id"`
	From   string `json:"from"`
	Label  string `json:"label"`
	ToID   string `json:"to_id"`
	To     string `json:"to"`
	// Confidence is the 0-100 score written on the edge if the proposal is
	// accepted; it comes from the correlator's signal weighting.
	Confidence int `json:"confidence"`
	// Signals are the short, human-readable reasons the pair was proposed, each
	// defined with its rationale in a signals data file (principle 8).
	Signals []string `json:"signals,omitempty"`
	// EvidenceIDs are stored asset or edge IDs a reviewer can inspect.
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	// Witness holds the evidence as the stored relationships the conclusion
	// rests on. It is the basis a re-check re-tests when new evidence arrives:
	// if a witnessed relationship is gone the conclusion is reconsidered, and a
	// stronger set of signals re-scores it (ai-design-principles.md: answers
	// carry evidence, and writes are reconsidered as the story changes). A
	// correlator should record here every relationship it read to decide.
	Witness []graph.WitnessEdge `json:"witness,omitempty"`
	// NewTo, when set, is the destination to create on approval (ToID is
	// empty): a unit a document names that no source has stored.
	NewTo *NewAsset `json:"new_to,omitempty"`
}

// RelationReport is the result of one correlator: the relationships it proposes.
// Kind names the correlator (for example "org_unit" or "horizontal"); it becomes
// the proposal-ID prefix and the `amass review <kind>` command, so one kind's
// proposals never collide with another's.
type RelationReport struct {
	Kind       string              `json:"kind"`
	Candidates []RelationCandidate `json:"candidates"`
	// Truncated names the limit that cut the search short, if any.
	Truncated string `json:"truncated,omitempty"`
}

// FormatRelationReport renders a correlator's proposed relationships as text,
// the same shape for every kind so a new correlator needs no formatter of its
// own. It describes candidates only; nothing is written until a reviewer
// accepts a proposal (amass review approve).
func FormatRelationReport(r RelationReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s correlation", r.Kind)
	if r.Truncated != "" {
		fmt.Fprintf(&b, " (truncated: %s)", r.Truncated)
	}
	b.WriteString("\n")
	if len(r.Candidates) == 0 {
		b.WriteString("No candidate relationships found.\n")
		return b.String()
	}
	for _, c := range r.Candidates {
		fmt.Fprintf(&b, "  %s --%s--> %s (confidence %d): %s\n", c.From, c.Label, c.To, c.Confidence,
			strings.Join(c.Signals, ", "))
	}

	return b.String()
}
