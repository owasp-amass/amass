// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/lens"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamgen "github.com/owasp-amass/open-asset-model/general"
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

// RecordAccount records a reviewer's decision on an account proposal, and the
// stored edge it created when applied.
func (j *Journal) RecordAccount(o AccountOutcome) error {
	if o.ProposalID == "" || o.Reviewer == "" {
		return errors.New("proposal ID and reviewer required")
	}
	if o.Status != ProposalApplied && o.Status != ProposalRejected && o.Status != ProposalRetracted {
		return fmt.Errorf("invalid account outcome status %q", o.Status)
	}
	if o.At.IsZero() {
		o.At = time.Now().UTC()
	}
	return j.append("account_outcome", o)
}

// accountRecords returns the account proposals in the journal and the latest
// status of each (proposed, applied, rejected or retracted).
func (j *Journal) accountRecords() (map[string]AccountProposal, map[string]string, error) {
	proposals := map[string]AccountProposal{}
	status := map[string]string{}
	hist, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return proposals, status, nil
	}
	if err != nil {
		return nil, nil, err
	}

	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil {
			continue
		}
		switch head.Kind {
		case "account_proposal":
			var p AccountProposal
			if json.Unmarshal(head.Data, &p) == nil && p.ID != "" {
				proposals[p.ID] = p
				status[p.ID] = ProposalPending
			}
		case "account_outcome":
			var o AccountOutcome
			if json.Unmarshal(head.Data, &o) == nil && o.ProposalID != "" {
				status[o.ProposalID] = o.Status
			}
		}
	}
	return proposals, status, nil
}

// PendingAccount returns an account proposal that is recorded and still
// awaiting a decision.
func (j *Journal) PendingAccount(id string) (AccountProposal, error) {
	proposals, status, err := j.accountRecords()
	if err != nil {
		return AccountProposal{}, err
	}
	p, ok := proposals[id]
	if !ok {
		return AccountProposal{}, fmt.Errorf("no account proposal %s", id)
	}
	if status[id] != ProposalPending {
		return AccountProposal{}, fmt.Errorf("account proposal %s is already %s", id, status[id])
	}
	return p, nil
}

// AppliedAccount returns an applied account proposal and the edge it created.
func (j *Journal) AppliedAccount(id string) (AccountProposal, string, error) {
	proposals, status, err := j.accountRecords()
	if err != nil {
		return AccountProposal{}, "", err
	}
	p, ok := proposals[id]
	if !ok || status[id] != ProposalApplied {
		return AccountProposal{}, "", fmt.Errorf("account proposal %s is not applied", id)
	}
	// Find the edge id from the applying outcome.
	hist, _ := j.History()
	var edgeID string
	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil || head.Kind != "account_outcome" {
			continue
		}
		var o AccountOutcome
		if json.Unmarshal(head.Data, &o) == nil && o.ProposalID == id && o.Status == ProposalApplied {
			edgeID = o.EdgeID
		}
	}
	return p, edgeID, nil
}

// AccountApplier writes the assets and relationships an accepted account
// proposal records.
type AccountApplier interface {
	FindEntityById(ctx context.Context, id string) (*dbt.Entity, error)
	CreateAsset(ctx context.Context, a oam.Asset) (*dbt.Entity, error)
	CreateEdge(ctx context.Context, e *dbt.Edge) (*dbt.Edge, error)
	CreateEntityProperty(ctx context.Context, e *dbt.Entity, p oam.Property) (*dbt.EntityTag, error)
	CreateEdgeProperty(ctx context.Context, e *dbt.Edge, p oam.Property) (*dbt.EdgeTag, error)
}

// AccountDeleter removes the edge an applied account proposal created.
type AccountDeleter interface {
	DeleteEdge(ctx context.Context, id string) error
}

// accountUniqueID is the stable key of a platform account, so the same
// account is one asset however many times it is recorded.
func accountUniqueID(p AccountProposal) string {
	return strings.ToLower(p.Platform) + ":" + strings.ToLower(p.Handle)
}

// ApplyAccount records an accepted account proposal as an Account asset the
// owning organization controls: Account plus an Organization -> account ->
// Account relationship, both tagged amass-ai. It returns the relationship's
// edge id.
func ApplyAccount(ctx context.Context, w AccountApplier, p AccountProposal) (string, error) {
	if p.OwnerID == "" || p.Handle == "" {
		return "", errors.New("account proposal needs an owner and handle")
	}
	org, err := w.FindEntityById(ctx, p.OwnerID)
	if err != nil || org == nil {
		return "", fmt.Errorf("owner %s not found: %w", p.OwnerID, err)
	}

	acct, err := w.CreateAsset(ctx, &oamacct.Account{ID: accountUniqueID(p), Type: p.AccountType, Username: p.Handle})
	if err != nil || acct == nil {
		return "", fmt.Errorf("create account %s: %w", accountUniqueID(p), err)
	}
	_, _ = w.CreateEntityProperty(ctx, acct, &oamgen.SourceProperty{Source: InferenceSource, Confidence: p.Confidence})

	edge, err := w.CreateEdge(ctx, &dbt.Edge{
		Relation:   &oamgen.SimpleRelation{Name: "account"},
		FromEntity: org,
		ToEntity:   acct,
	})
	if err != nil || edge == nil {
		return "", fmt.Errorf("link %s to account: %w", p.Owner, err)
	}
	_, _ = w.CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{Source: InferenceSource, Confidence: p.Confidence})

	return edge.ID, nil
}
