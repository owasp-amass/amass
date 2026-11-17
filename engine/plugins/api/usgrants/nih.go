// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
)

// nihResponse is the NIH RePORTER v2 project search response
// (api.reporter.nih.gov/v2/projects/search).
type nihResponse struct {
	Results []struct {
		ProjectNum   string  `json:"project_num"`
		AwardAmount  float64 `json:"award_amount"`
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
		out = append(out, grant{
			id:        "nih:" + p.ProjectNum,
			amount:    p.AwardAmount,
			date:      date,
			agency:    firstNonEmpty(p.AgencyIcAdmin.Name, "National Institutes of Health"),
			recipient: p.Organization.OrgName,
		})
	}
	return out, nil
}

func queryNIH(h *source, e *et.Event, orgent *dbt.Entity, name string) {
	req := map[string]any{
		"criteria": map[string]any{"org_names": []string{name}},
		"include_fields": []string{"ProjectNum", "AwardAmount", "Organization",
			"AgencyIcAdmin", "FiscalYear", "ProjectStartDate"},
		"limit":  50,
		"offset": 0,
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
		if !recipientMatches(name, g.recipient) || seen[g.id] {
			continue
		}
		seen[g.id] = true
		h.store(e, orgent, g)
	}
}
