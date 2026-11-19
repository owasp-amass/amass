// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// reservedProposalPrefixes are the proposal-ID prefixes that belong to the
// specific proposal kinds (ownership, accounts, merges, identity corrections,
// organizations-under-a-person's-name). A relation proposal's ID is
// "<correlator kind>-<hash>", so any well-formed proposal ID whose prefix is not
// one of these is a relation proposal — which means a new correlator kind is
// reviewable with no change here (ai-design-principles.md, principles 9 & 10).
var reservedProposalPrefixes = []string{
	"own-", "acct-", review.DuplicatePrefix, review.PersonDuplicatePrefix,
	lens.IdentityPrefix, lens.PersonNamedPrefix,
}

// isRelationProposal reports whether an ID names a relation proposal produced by
// a Goal-2 correlator. Relation IDs are "<kind>-<16 hex>"; the kind is any label
// that is not one of the reserved specific-proposal prefixes.
func isRelationProposal(id string) bool {
	i := strings.LastIndexByte(id, '-')
	// Need a non-empty kind, a '-', and exactly 16 lowercase hex digits
	// (RelationProposalID uses hex of the first 8 hash bytes).
	if i <= 0 || len(id)-i-1 != 16 {
		return false
	}
	for _, c := range id[i+1:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	for _, p := range reservedProposalPrefixes {
		if strings.HasPrefix(id, p) {
			return false
		}
	}

	return true
}

// listRelatedDomains runs the horizontal related-domains lens for one
// organization and prints the apex domains the signals tie to it, read-only.
// The domains are candidates a reviewer confirms before scope grows; the lens
// never changes scope itself (horizontal-domain-correlation-spec.md).
func listRelatedDomains(ctx context.Context, g oamrepo.Adapter, domain, org, format string, out io.Writer) error {
	if strings.TrimSpace(org) == "" {
		return errors.New("related-domains needs -org <name> (the organization to find related domains for)")
	}

	root, err := groupRoot(ctx, g, domain, org)
	if err != nil {
		return err
	}

	r, err := lens.FindRelatedDomains(ctx, g, root.ID)
	if err != nil {
		return err
	}

	switch format {
	case "text":
		_, err := fmt.Fprint(out, lens.FormatRelatedDomainsReport(r))
		return err
	case "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("related-domains format %q: use text or json", format)
}

// listRelatedInfrastructure runs the infrastructure-correlation lens for one
// organization and prints the netblocks and autonomous systems the signals tie
// to it, read-only.
func listRelatedInfrastructure(ctx context.Context, g oamrepo.Adapter, domain, org, format string,
	out io.Writer) error {
	if strings.TrimSpace(org) == "" {
		return errors.New("related-infrastructure needs -org <name> (the organization to find infrastructure for)")
	}

	root, err := groupRoot(ctx, g, domain, org)
	if err != nil {
		return err
	}

	r, err := lens.FindRelatedInfrastructure(ctx, g, root.ID)
	if err != nil {
		return err
	}

	switch format {
	case "text":
		_, err := fmt.Fprint(out, lens.FormatRelatedInfrastructureReport(r))
		return err
	case "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("related-infrastructure format %q: use text or json", format)
}

// listOrgUnits scans the Asset Database for organizations that are units of a
// parent organization and records each as a review-gated relation proposal;
// nothing in the database changes until a reviewer approves it. It mirrors the
// db-hygiene scans (person-duplicates): a whole-database pass that only
// proposes.
func listOrgUnits(ctx context.Context, g graph.Graph, journalPath, format string, explicit bool,
	out, errout io.Writer) error {
	r, err := lens.FindOrgUnits(ctx, g)
	if err != nil {
		return err
	}

	if journalPath != "" {
		added, err := (&review.Journal{Path: journalPath}).SubmitRelations(review.RelationProposals(r))
		if err != nil {
			return fmt.Errorf("record org-unit proposals: %w", err)
		}

		_, _ = fmt.Fprintf(errout, "%d new org-unit proposal(s) recorded in %s; review with "+
			"`amass review proposals` and accept with `amass review approve -proposal <id> -reviewer <you>`\n",
			len(added), journalPath)
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatRelationReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("org-units format %q: use text or json", format)
}

// approveRelation writes an accepted relation proposal's edge, tagged amass-ai
// with the proposal's confidence, and records the apply so it can be undone.
func approveRelation(ctx context.Context, w review.RelationApplier, journalPath, id, reviewer string,
	out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	j := &review.Journal{Path: journalPath}
	p, err := j.PendingRelation(id)
	if err != nil {
		return err
	}

	edgeID, err := review.ApplyRelation(ctx, w, j, p, reviewer)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Linked %s --%s--> %s as edge %s (source %s, confidence %d). Undo with "+
		"`amass review retract -proposal %s -reviewer %s`.\n", p.From, p.Label, p.To, edgeID,
		review.InferenceSource, p.Confidence, id, reviewer)
	return err
}

// retractRelation removes the edge an applied relation proposal created and
// records the retraction, so automatic re-checking never writes it again.
func retractRelation(ctx context.Context, d review.RelationDeleter, journalPath, id, reviewer string,
	out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	j := &review.Journal{Path: journalPath}
	p, _, err := j.AppliedRelation(id)
	if err != nil {
		return err
	}
	if err := review.RetractRelation(ctx, d, j, id, reviewer); err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Removed %s --%s--> %s.\n", p.From, p.Label, p.To)
	return err
}
