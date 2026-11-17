// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/lens"
)

// AccountProposal is a reviewed-before-written proposal to record a platform
// account an organization controls, computed by the accounts lens from a
// stored profile URL (the evidence). It is the bridge from a computed
// conclusion to a stored observation: the account becomes an Account asset
// only when a reviewer accepts the proposal (ai-design-principles.md,
// principle 9).
type AccountProposal struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	OwnerID     string `json:"owner_id"`
	Platform    string `json:"platform"`
	AccountType string `json:"account_type"`
	Handle      string `json:"handle"`
	// EvidenceURL is the profile URL the account was derived from, and
	// EvidenceID its stored URL asset.
	EvidenceURL string    `json:"evidence_url"`
	EvidenceID  string    `json:"evidence_id,omitempty"`
	Confidence  int       `json:"confidence"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// AccountOutcome records a reviewer's decision on an account proposal, and the
// stored edge it created when applied.
type AccountOutcome struct {
	ProposalID string    `json:"proposal_id"`
	Status     string    `json:"status"`
	Reviewer   string    `json:"reviewer"`
	EdgeID     string    `json:"edge_id,omitempty"`
	At         time.Time `json:"at"`
}

// AccountProposalID is a stable identifier for an organization's account on a
// platform, so the same account is not proposed twice.
func AccountProposalID(ownerID, platform, handle string) string {
	sum := sha256.Sum256([]byte(ownerID + "\x00" + strings.ToLower(platform) + "\x00" + strings.ToLower(handle)))
	return "acct-" + hex.EncodeToString(sum[:8])
}

// AccountProposals turns an accounts-lens report into proposals: one per
// recognized account, attributed to the subject's owning organization. The
// lens only reports accounts it recognized from a catalogued platform URL, so
// these are the high-confidence derivations.
func AccountProposals(r lens.AccountsReport) []AccountProposal {
	if r.OwnerID == "" {
		return nil
	}

	var out []AccountProposal
	now := time.Now().UTC()
	for _, a := range r.Accounts {
		if a.Platform == "" || a.Handle == "" {
			continue
		}
		out = append(out, AccountProposal{
			ID:          AccountProposalID(r.OwnerID, a.Platform, a.Handle),
			Owner:       r.Owner,
			OwnerID:     r.OwnerID,
			Platform:    a.Platform,
			AccountType: a.Type,
			Handle:      a.Handle,
			EvidenceURL: a.URL,
			EvidenceID:  a.URLID,
			Confidence:  90,
			Status:      ProposalPending,
			CreatedAt:   now,
		})
	}

	return out
}

// accountProposalIDs returns the IDs of the account proposals already in the
// journal, so SubmitAccounts does not record a duplicate.
func (j *Journal) accountProposalIDs() (map[string]bool, error) {
	ids := map[string]bool{}
	hist, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return ids, nil
	}
	if err != nil {
		return nil, err
	}

	for _, raw := range hist {
		var rec struct {
			Kind string `json:"kind"`
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(raw, &rec) == nil && rec.Kind == "account_proposal" && rec.Data.ID != "" {
			ids[rec.Data.ID] = true
		}
	}
	return ids, nil
}

// SubmitAccounts records the account proposals not already in the journal and
// returns the ones it added.
func (j *Journal) SubmitAccounts(proposals []AccountProposal) ([]AccountProposal, error) {
	seen, err := j.accountProposalIDs()
	if err != nil {
		return nil, err
	}

	var added []AccountProposal
	for _, p := range proposals {
		if p.ID == "" || p.OwnerID == "" || p.Handle == "" {
			return added, errors.New("account proposal needs an ID, owner and handle")
		}
		if seen[p.ID] {
			continue
		}
		if err := j.append("account_proposal", p); err != nil {
			return added, err
		}
		seen[p.ID] = true
		added = append(added, p)
	}

	return added, nil
}
