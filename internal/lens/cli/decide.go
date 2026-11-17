// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"fmt"

	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
)

// Review decisions.
const (
	DecisionApprove = "approve"
	DecisionReject  = "reject"
	DecisionRetract = "retract"
)

// ProposalsText lists the journal's proposals as amass review proposals
// does.
func ProposalsText(journalPath string) (string, error) {
	var out bytes.Buffer
	err := listProposals(journalPath, "text", false, &out)
	return out.String(), err
}

// PendingProposalsText lists only the proposals awaiting a decision, so the
// assistant can surface newly-proposed items for immediate review without
// wading through already-decided ones.
func PendingProposalsText(journalPath string) (string, error) {
	var out bytes.Buffer
	err := pendingProposals(journalPath, &out)
	return out.String(), err
}

// Decide approves, rejects or retracts a proposal of any kind as amass
// review does, and returns what it reports. Approving and retracting write
// to the Asset Database through g; rejecting only appends to the journal.
func Decide(ctx context.Context, g oamrepo.Adapter, journalPath, decision, id, reviewer string) (string, error) {
	var out bytes.Buffer
	var err error
	switch decision {
	case DecisionReject:
		err = rejectProposal(journalPath, id, reviewer, &out)
	case DecisionApprove:
		switch {
		case isPersonNamedProposal(id):
			err = approvePersonNamed(ctx, g, journalPath, id, reviewer, &out)
		case isIdentityProposal(id):
			err = approveIdentity(ctx, g, journalPath, id, reviewer, &out)
		case isMergeProposal(id):
			err = approveMerge(ctx, g, journalPath, id, reviewer, &out)
		default:
			err = approveProposal(ctx, g, journalPath, id, reviewer, &out)
		}
	case DecisionRetract:
		switch {
		case isPersonNamedProposal(id):
			err = retractPersonNamed(ctx, g, journalPath, id, reviewer, &out)
		case isIdentityProposal(id):
			err = retractIdentity(ctx, g, journalPath, id, reviewer, &out)
		case isMergeProposal(id):
			err = retractMerge(ctx, g, journalPath, id, reviewer, &out)
		default:
			err = retractProposal(ctx, g, journalPath, id, reviewer, &out)
		}
	default:
		err = fmt.Errorf("decision must be %s, %s or %s", DecisionApprove, DecisionReject, DecisionRetract)
	}

	return out.String(), err
}
