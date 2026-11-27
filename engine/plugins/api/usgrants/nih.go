// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"cmp"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
)

// nihResponse is the NIH RePORTER v2 project search response
// (api.reporter.nih.gov/v2/projects/search).
type nihResponse struct {
	Results []struct {
		ProjectNum   string  `json:"project_num"`
		AwardAmount  float64 `json:"award_amount"`
		DirectCost   float64 `json:"direct_cost_amt"`
		IndirectCost float64 `json:"indirect_cost_amt"`
		AgencyFunds  []struct {
			TotalCost float64 `json:"total_cost"`
		} `json:"agency_ic_fundings"`
		Organization struct {
			OrgName string `json:"org_name"`
		} `json:"organization"`
		AgencyIcAdmin struct {
			Name string `json:"name"`
		} `json:"agency_ic_admin"`
		FiscalYear       int    `json:"fiscal_year"`
		ProjectStartDate string `json:"project_start_date"`
	} `json:"results"`
}

func parseNIH(body []byte) ([]grant, error) {
	var r nihResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	var out []grant
	for _, p := range r.Results {
		date := p.ProjectStartDate
		if date == "" && p.FiscalYear > 0 {
			date = strconv.Itoa(p.FiscalYear)
		}
		// Prefer award_amount; when a record omits it, fall back to the
		// direct+indirect split and then the per-institute funding totals,
		// so a grant with real funding is not stored as amountless.
		amount := p.AwardAmount
		if amount == 0 {
			amount = p.DirectCost + p.IndirectCost
		}
		if amount == 0 {
			for _, f := range p.AgencyFunds {
				amount += f.TotalCost
			}
		}
		out = append(out, grant{
			id:        "nih:" + p.ProjectNum,
			amount:    amount,
			date:      date,
			agency:    cmp.Or(p.AgencyIcAdmin.Name, "National Institutes of Health"),
			recipient: p.Organization.OrgName,
		})
	}
	return out, nil
}

func queryNIH(h *source, e *et.Event, orgent *dbt.Entity, name string) {
	// Request the full record rather than an include_fields projection: the
	// fallback cost fields (direct_cost_amt, indirect_cost_amt,
	// agency_ic_fundings) are always present in the full record, so there is
	// no projection token to get wrong.
	req := map[string]any{
		"criteria": map[string]any{"org_names": []string{name}},
		"limit":    50,
		"offset":   0,
	}
	bodyJSON, err := json.Marshal(req)
	if err != nil {
		return
	}

	body, err := h.postJSON(e, "https://api.reporter.nih.gov/v2/projects/search", string(bodyJSON))
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("NIH query for %s failed: %s", name, err),
			slog.Group("plugin", "name", h.name))
		return
	}
	grants, err := parseNIH([]byte(body))
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("failed to parse NIH awards for %s: %s", name, err),
			slog.Group("plugin", "name", h.name))
		return
	}

	seen := map[string]bool{}
	for i := range grants {
		g := &grants[i]
		if !semantics.SameOrgName(name, g.recipient) || seen[g.id] {
			continue
		}
		seen[g.id] = true
		h.store(e, orgent, g)
	}
}
