// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// FamilyProposals turns a family report into proposals for review: an
// org_unit relationship from the main organization to each department,
// and a merge of each organization that is the same institution as the
// main one. Affiliates are only reported; nothing records them.
func FamilyProposals(r lens.FamilyReport) ([]OwnershipProposal, []DuplicateProposal) {
	if r.Main == nil {
		return nil, nil
	}

	now := time.Now().UTC()
	main := *r.Main
	var units []OwnershipProposal
	var merges []DuplicateProposal
	for _, m := range r.Members {
		if m.Organization.ID == main.ID {
			continue
		}

		evidence := append([]string{"family of " + r.Domain}, m.Evidence...)
		switch m.Relation {
		case lens.FamilyDepartment:
			edge := lens.ProposedEdge{FromID: main.ID, FromType: "Organization", From: graph.AssetLabel(main), Label: "org_unit",
				RelationType: "SimpleRelation", ToID: m.Organization.ID, ToType: "Organization",
				To: graph.AssetLabel(m.Organization)}
			units = append(units, OwnershipProposal{ID: ProposalID(edge), Kind: ProposalKindOrgUnit,
				Owner: graph.AssetLabel(main), OwnerID: main.ID, Asset: graph.AssetLabel(m.Organization),
				AssetID: m.Organization.ID, AssetType: "Organization", Edge: edge, Decision: lens.GapReview,
				Signals: evidence, Evidence: evidence, CreatedAt: now})
		case lens.FamilySame:
			if !m.ByName {
				// A shared address alone is reported, never merged.
				continue
			}
			survivor, dup := main, m.Organization
			merges = append(merges, DuplicateProposal{ID: DuplicateProposalID(survivor, dup),
				Survivor: graph.AssetLabel(survivor), SurvivorID: survivor.ID, Duplicate: graph.AssetLabel(dup), DuplicateID: dup.ID,
				Decision: lens.GapReview, Signals: evidence, CreatedAt: now})
		}
	}

	return units, merges
}

// SubmitFamily records in j a family's department and merge proposals not
// already in the journal and returns how many of each it added.
func SubmitFamily(j *Journal, r lens.FamilyReport) (int, int, error) {
	units, merges := FamilyProposals(r)
	addedUnits, err := j.SubmitOwnership(units)
	if err != nil {
		return 0, 0, fmt.Errorf("record department proposals: %w", err)
	}

	addedMerges, err := j.SubmitDuplicates(merges)
	if err != nil {
		return len(addedUnits), 0, fmt.Errorf("record merge proposals: %w", err)
	}

	return len(addedUnits), len(addedMerges), nil
}
