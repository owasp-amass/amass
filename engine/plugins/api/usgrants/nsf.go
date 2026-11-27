// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
)

// nsfResponse is the NSF Award Search response
// (api.nsf.gov/services/v1/awards.json).
type nsfResponse struct {
	Response struct {
		Award []struct {
			ID                string `json:"id"`
			AwardeeName       string `json:"awardeeName"`
			FundsObligatedAmt string `json:"fundsObligatedAmt"`
			Agency            string `json:"agency"`
			Date              string `json:"date"`
		} `json:"award"`
	} `json:"response"`
}

func parseNSF(body []byte) ([]grant, error) {
	var r nsfResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	var out []grant
	for _, a := range r.Response.Award {
		amt, _ := strconv.ParseFloat(strings.TrimSpace(a.FundsObligatedAmt), 64)
		// NSF awards are all from NSF; store the full name as the funder.
		out = append(out, grant{
			id:        "nsf:" + a.ID,
			amount:    amt,
			date:      a.Date,
			agency:    "National Science Foundation",
			recipient: a.AwardeeName,
		})
	}
	return out, nil
}

func queryNSF(h *source, e *et.Event, orgent *dbt.Entity, name string) {
	u := "https://api.nsf.gov/services/v1/awards.json?printFields=id,awardeeName,fundsObligatedAmt,agency,date&awardeeName=" +
		url.QueryEscape(`"`+name+`"`)

	body, err := h.get(e, u)
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("NSF query for %s failed: %s", name, err),
			slog.Group("plugin", "name", h.name))
		return
	}
	grants, err := parseNSF([]byte(body))
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("failed to parse NSF awards for %s: %s", name, err),
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
