// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// ScopeExpansionPrefix prefixes the id of a horizontal scope-expansion record,
// so it is never mistaken for another kind of proposal.
const ScopeExpansionPrefix = "hdom-"

// ScopeExpansion records a registered (apex) domain the scored horizontal
// correlation added to, or proposed for, an enumeration's scope, with the
// evidence behind it. It makes a runtime scope change auditable and reversible:
// the reevaluation sweep re-tests an applied expansion as the enumeration brings
// in new evidence and retracts it if the evidence no longer supports it, so
// scope is never silently or permanently grown on a stale conclusion
// (ai-design-principles.md, principles 9 & 13). An applied expansion was added
// to scope during the run; a pending one is corroboration-only and waits for a
// person; a retracted one was reconsidered and removed.
type ScopeExpansion struct {
	ID         string              `json:"id"`
	OrgID      string              `json:"org_id"`
	Org        string              `json:"org"`
	Domain     string              `json:"domain"`
	Confidence int                 `json:"confidence"`
	Signals    []string            `json:"signals,omitempty"`
	SignalIDs  []string            `json:"signal_ids,omitempty"`
	Witness    []graph.WitnessEdge `json:"witness,omitempty"`
	Status     string              `json:"status"`
	Reviewer   string              `json:"reviewer,omitempty"`
	At         time.Time           `json:"at"`
}

// ScopeExpansionID is a stable identifier for an organization/domain scope
// expansion, so the same expansion is recorded once and a reconsidered one is
// recognized rather than duplicated.
func ScopeExpansionID(orgID, domain string) string {
	sum := sha256.Sum256([]byte(orgID + "\x00" + domain))
	return ScopeExpansionPrefix + hex.EncodeToString(sum[:8])
}

// RecordScopeExpansion appends a scope-expansion record — applied, pending
// review, or retracted — filling the id and timestamp when unset.
func (j *Journal) RecordScopeExpansion(e ScopeExpansion) error {
	if e.OrgID == "" || e.Domain == "" {
		return errors.New("scope expansion needs an organization and a domain")
	}
	if e.Status != ProposalApplied && e.Status != ProposalPending && e.Status != ProposalRetracted {
		return fmt.Errorf("invalid scope-expansion status %q", e.Status)
	}
	if e.ID == "" {
		e.ID = ScopeExpansionID(e.OrgID, e.Domain)
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}

	return j.append("scope_expansion", e)
}

// ScopeExpansions returns the latest record for each scope expansion, in the
// order the expansions were first recorded, so applied and reconsidered
// expansions can be listed and re-checked.
func (j *Journal) ScopeExpansions() ([]ScopeExpansion, error) {
	hist, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	latest := map[string]ScopeExpansion{}
	var order []string
	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil || head.Kind != "scope_expansion" {
			continue
		}
		var e ScopeExpansion
		if json.Unmarshal(head.Data, &e) != nil || e.ID == "" {
			continue
		}
		if _, seen := latest[e.ID]; !seen {
			order = append(order, e.ID)
		}
		latest[e.ID] = e
	}

	out := make([]ScopeExpansion, 0, len(order))
	for _, id := range order {
		out = append(out, latest[id])
	}

	return out, nil
}

// AppliedScopeExpansions returns the expansions whose latest record is applied —
// the ones currently in scope — for the reevaluation sweep.
func (j *Journal) AppliedScopeExpansions() ([]ScopeExpansion, error) {
	all, err := j.ScopeExpansions()
	if err != nil {
		return nil, err
	}

	var out []ScopeExpansion
	for _, e := range all {
		if e.Status == ProposalApplied {
			out = append(out, e)
		}
	}

	return out, nil
}
