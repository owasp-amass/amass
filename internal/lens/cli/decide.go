// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// Review decisions.
const (
	DecisionApprove = "approve"
	DecisionReject  = "reject"
	DecisionRetract = "retract"
)

// ProposalsText lists the journal's proposals as amass review proposals
// does.
func ProposalsText(j *review.Journal) (string, error) {
	var out bytes.Buffer
	err := listProposals(j, "text", false, &out)
	return out.String(), err
}

// PendingProposalsText lists only the proposals awaiting a decision, so the
// assistant can surface newly-proposed items for immediate review without
// wading through already-decided ones.
func PendingProposalsText(j *review.Journal) (string, error) {
	var out bytes.Buffer
	err := pendingProposals(j, &out)
	return out.String(), err
}

// PendingProposalsTextLive is PendingProposalsText, hiding the proposals
// whose entities are no longer in the database (exists), with a count of how
// many it hid.
func PendingProposalsTextLive(j *review.Journal, exists EntityExists) (string, error) {
	var out bytes.Buffer
	err := pendingProposalsLive(j, exists, &out)
	return out.String(), err
}

// Decide approves, rejects or retracts a proposal of any kind as amass
// review does, and returns what it reports. Approving and retracting write
// to the Asset Database through g; rejecting only appends to the journal.
// as says what an approved name proposal names (person or organization);
// it is required for those and refused for every other kind. Approving or
// rejecting a name proposal decides every pending one of the same name in
// the same field, unless only is set.
func Decide(ctx context.Context, g oamrepo.Adapter, j *review.Journal, decision, id, as, reviewer string,
	only bool) (string, error) {
	if as != "" && (decision != DecisionApprove || !review.IsNameKindProposal(id)) {
		return "", errors.New("-as is only for approving a name proposal (nk-...)")
	}
	if review.IsContribution(id) && decision != DecisionRetract {
		return "", errors.New("a contribution was applied when it was approved; retract it to undo it")
	}
	if only && (decision == DecisionRetract || !review.IsNameKindProposal(id)) {
		return "", errors.New("-only is only for approving or rejecting a name proposal (nk-...)")
	}

	var out bytes.Buffer
	var err error
	switch decision {
	case DecisionReject:
		if review.IsNameKindProposal(id) {
			err = rejectNameKind(j, id, reviewer, only, &out)
			break
		}
		err = rejectProposal(j, id, reviewer, &out)
	case DecisionApprove:
		switch {
		case review.IsScopeExpansion(id):
			// before isRelationProposal, whose pattern its IDs also fit
			err = decideScopeExpansion(j, id, review.ProposalApplied, reviewer, &out)
		case review.IsOrgNamedProposal(id):
			err = approveOrgNamed(ctx, g, j, id, reviewer, &out)
		case review.IsNameKindProposal(id):
			err = approveNameKind(ctx, g, j, id, as, reviewer, only, &out)
		case isPersonNamedProposal(id):
			err = approvePersonNamed(ctx, g, j, id, reviewer, &out)
		case isIdentityProposal(id):
			err = approveIdentity(ctx, g, j, id, reviewer, &out)
		case isMergeProposal(id):
			err = approveMerge(ctx, g, j, id, reviewer, &out)
		case isAccountProposal(id):
			err = approveAccount(ctx, g.Repo, j, id, reviewer, &out)
		case isRelationProposal(id):
			err = approveRelation(ctx, g.Repo, j, id, reviewer, &out)
		default:
			err = approveProposal(ctx, g, j, id, reviewer, &out)
		}
	case DecisionRetract:
		switch {
		case review.IsOrgNamedProposal(id):
			err = retractOrgNamed(ctx, g, j, id, reviewer, &out)
		case review.IsNameKindProposal(id):
			err = retractNameKind(ctx, g, j, id, reviewer, &out)
		case isPersonNamedProposal(id):
			err = retractPersonNamed(ctx, g, j, id, reviewer, &out)
		case isIdentityProposal(id):
			err = retractIdentity(ctx, g, j, id, reviewer, &out)
		case isMergeProposal(id):
			err = retractMerge(ctx, g, j, id, reviewer, &out)
		case isAccountProposal(id):
			err = retractAccount(ctx, g.Repo, j, id, reviewer, &out)
		case review.IsScopeExpansion(id):
			// before isRelationProposal, whose pattern its IDs also fit
			err = retractScopeExpansion(j, id, reviewer, &out)
		case isRelationProposal(id):
			err = retractRelation(ctx, g.Repo, j, id, reviewer, &out)
		case isDocumentDecision(id):
			err = retractDocument(ctx, g.Repo, j, id, reviewer, &out)
		case review.IsContribution(id):
			err = retractContribution(ctx, g, j, id, reviewer, &out)
		default:
			err = retractProposal(ctx, g, j, id, reviewer, &out)
		}
	default:
		err = fmt.Errorf("decision must be %s, %s or %s", DecisionApprove, DecisionReject, DecisionRetract)
	}

	return out.String(), err
}

// retractContribution undoes an assistant's contribution: its source tags,
// and what only it recorded.
func retractContribution(ctx context.Context, w review.ContributionWriter, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	if err := review.RetractContribution(ctx, w, j, id, reviewer); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Retracted %s; what only it recorded was removed.\n", id)
	return err
}
