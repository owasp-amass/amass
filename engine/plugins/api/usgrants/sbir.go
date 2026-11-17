// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
)

// sbirAward is one SBIR/STTR award (api.www.sbir.gov/public/api/awards). The
// award endpoint is less documented than the others and has been under
// maintenance, so numeric fields are decoded flexibly (they may arrive as a
// number or a string) and the shape is worth validating against a live sample.
type sbirAward struct {
	Firm        string          `json:"firm"`
	Agency      string          `json:"agency"`
	Contract    string          `json:"contract"`
	AwardTitle  string          `json:"award_title"`
	AwardYear   json.RawMessage `json:"award_year"`
	AwardAmount json.RawMessage `json:"award_amount"`
}

// sbirAwards unwraps the response whether it is a bare array or wrapped.
func parseSBIR(body []byte) ([]grant, error) {
	var arr []sbirAward
	if err := json.Unmarshal(body, &arr); err != nil {
		// Some deployments wrap the list; tolerate that too.
		var wrapped struct {
			Results []sbirAward `json:"results"`
			Awards  []sbirAward `json:"awards"`
		}
		if json.Unmarshal(body, &wrapped) != nil {
			return nil, err
		}
		arr = wrapped.Results
		if len(arr) == 0 {
			arr = wrapped.Awards
		}
	}

	var out []grant
	for _, a := range arr {
		year := flexStr(a.AwardYear)
		id := "sbir:" + a.Contract
		if a.Contract == "" {
			id = "sbir:" + strings.ReplaceAll(strings.TrimSpace(a.AwardTitle), " ", "_") + ":" + year
		}
		out = append(out, grant{
			id:        id,
			amount:    flexNum(a.AwardAmount),
			date:      year,
			agency:    a.Agency,
			recipient: a.Firm,
		})
	}
	return out, nil
}

func querySBIR(h *source, e *et.Event, orgent *dbt.Entity, name string) {
	u := "https://api.www.sbir.gov/public/api/awards?format=json&firm=" + url.QueryEscape(name)

	body, err := h.get(e, u)
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("SBIR query for %s failed: %s", name, err),
			slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}
	grants, err := parseSBIR([]byte(body))
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("failed to parse SBIR awards for %s: %s", name, err),
			slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}

	seen := map[string]bool{}
	for i := range grants {
		g := &grants[i]
		if g.id == "sbir:" || !recipientMatches(name, g.recipient) || seen[g.id] {
			continue
		}
		seen[g.id] = true
		h.store(e, orgent, g)
	}
}
