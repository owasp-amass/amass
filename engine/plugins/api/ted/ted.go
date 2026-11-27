// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ted

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

const tedMaxResults = 50

// notice is one TED search result; field values are decoded flexibly because
// TED returns them as a scalar, a list, or a language-keyed map depending on
// the field and version.
type notice map[string]json.RawMessage

// tedResponse covers the two wrapper keys TED has used for the result list.
type tedResponse struct {
	Notices []notice `json:"notices"`
	Results []notice `json:"results"`
}

func (r *tedResponse) list() []notice {
	if len(r.Notices) > 0 {
		return r.Notices
	}
	return r.Results
}

// parseNotices reads a TED search response into its notices.
func parseNotices(body []byte) ([]notice, error) {
	var r tedResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	return r.list(), nil
}

func (h *awards) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.FundsTransfer), h.plugin.name)
	if err != nil {
		return err
	}

	src := &et.Source{Name: h.name, Confidence: h.plugin.source.Confidence}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		return nil
	}
	h.query(e, e.Entity, o.Name)
	support.MarkAssetMonitored(e.Session, e.Entity, src)
	return nil
}

func (h *awards) query(e *et.Event, orgent *dbt.Entity, name string) {
	req := map[string]any{
		"query": fmt.Sprintf(`winner-name=%q SORT BY publication-date DESC`, name),
		"fields": []string{"publication-number", "winner-name", "buyer-name",
			"total-value", "total-value-cur", "tender-value", "tender-value-cur",
			"publication-date", "winner-decision-date"},
		"page":           1,
		"limit":          tedMaxResults,
		"scope":          "ALL",
		"paginationMode": "PAGE_NUMBER",
	}
	bodyJSON, err := json.Marshal(req)
	if err != nil {
		return
	}

	_ = support.WaitLimit(e.Session.Ctx(), h.plugin.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    h.plugin.api + "/notices/search",
		Method: "POST",
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}},
		Body:   string(bodyJSON),
	})
	e.Session.NetSem().Release()
	cancel()
	if err != nil || resp.StatusCode != 200 || resp.Body == "" {
		if err != nil {
			e.Session.Log().Error(fmt.Sprintf("TED query for %s failed: %s", name, err),
				slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		}
		return
	}

	notices, err := parseNotices([]byte(resp.Body))
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("failed to parse the TED response for %s: %s", name, err),
			slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}

	seen := map[string]bool{}
	for _, n := range notices {
		// The winner match is the attribution; the amount may be absent on the
		// summary notice, falling back to the tender value.
		if !winnerMatches(name, support.JSONStrings(n["winner-name"])) {
			continue
		}
		amount := support.JSONNumber(n["total-value"])
		currency := support.JSONString(n["total-value-cur"])
		if amount == 0 {
			amount = support.JSONNumber(n["tender-value"])
			if currency == "" {
				currency = support.JSONString(n["tender-value-cur"])
			}
		}

		id := support.JSONString(n["publication-number"])
		if id == "" {
			id = fmt.Sprintf("%s:%.0f", support.JSONString(n["publication-date"]), amount)
		}
		if seen[id] {
			continue
		}
		seen[id] = true

		h.store(e, orgent, &award{
			id:       id,
			amount:   amount,
			currency: currency,
			date:     cmp.Or(support.JSONString(n["winner-decision-date"]), support.JSONString(n["publication-date"])),
			buyer:    support.JSONString(n["buyer-name"]),
		})
	}
}

type award struct {
	id, currency, date, buyer string
	amount                    float64
}

func (h *awards) store(e *et.Event, orgent *dbt.Entity, a *award) {
	currency := a.currency
	if currency == "" {
		currency = "EUR"
	}
	// The contracting authority (buyer) is the funding party.
	if fundent := org.StoreReceivedTransfer(e, orgent, org.ReceivedTransfer{
		ID: "ted:" + a.id, Reference: a.id, Amount: a.amount, Currency: currency, Date: a.date, Funder: a.buyer,
	}, h.plugin.source); fundent != nil {
		org.DispatchTransfers(e, fundent)
	}
}

// winnerMatches reports whether any winner name on a notice is the subject
// organization's name (semantics.SameOrgName).
func winnerMatches(orgName string, winners []string) bool {
	return slices.ContainsFunc(winners, func(w string) bool { return semantics.SameOrgName(orgName, w) })
}
