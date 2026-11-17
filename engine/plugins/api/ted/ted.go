// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ted

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
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
			"total-value", "total-value-cur", "publication-date", "winner-decision-date"},
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
		if !winnerMatches(name, flexStrings(n["winner-name"])) {
			continue
		}
		amount := flexFloat(n["total-value"])
		if amount <= 0 {
			continue
		}
		id := first(flexStrings(n["publication-number"]))
		if id == "" {
			id = fmt.Sprintf("%s:%.0f", first(flexStrings(n["publication-date"])), amount)
		}
		if seen[id] {
			continue
		}
		seen[id] = true

		h.store(e, orgent, &award{
			id:       id,
			amount:   amount,
			currency: first(flexStrings(n["total-value-cur"])),
			date:     firstNonEmpty(first(flexStrings(n["winner-decision-date"])), first(flexStrings(n["publication-date"]))),
			buyer:    first(flexStrings(n["buyer-name"])),
		})
	}
}

type award struct {
	id, currency, date, buyer string
	amount                    float64
}

func (h *awards) store(e *et.Event, orgent *dbt.Entity, a *award) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	orgacc := h.orgCheckingAccount(e, orgent)
	if orgacc == nil {
		return
	}

	currency := a.currency
	if currency == "" {
		currency = "EUR"
	}
	fundent, err := e.Session.DB().CreateAsset(ctx, &oamfin.FundsTransfer{
		ID:              "ted:" + a.id,
		Amount:          a.amount,
		Currency:        currency,
		ReferenceNumber: a.id,
		ExchangeDate:    a.date,
	})
	if err != nil || fundent == nil {
		return
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, fundent, &general.SourceProperty{
		Source: h.plugin.source.Name, Confidence: h.plugin.source.Confidence,
	})
	if err := h.plugin.createRelation(ctx, e.Session, fundent,
		&general.SimpleRelation{Name: "recipient"}, orgacc, h.plugin.source.Confidence); err != nil {
		return
	}

	// The contracting authority (buyer) is the funding party.
	if buyer := h.buyerOrg(e, a.buyer); buyer != nil {
		_ = h.plugin.createRelation(ctx, e.Session, fundent,
			&general.SimpleRelation{Name: "third_party"}, buyer, h.plugin.source.Confidence)
	}

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name: fmt.Sprintf("%f:ted:%s", a.amount, a.id), Entity: fundent, Session: e.Session,
	})
}

func (h *awards) buyerOrg(e *et.Event, name string) *dbt.Entity {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	orgent, err := org.CreateOrgAsset(e.Session, nil, nil, &oamorg.Organization{Name: name}, h.plugin.source)
	if err != nil || orgent == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()
	_, _ = e.Session.DB().CreateEntityProperty(ctx, orgent, &general.SourceProperty{
		Source: h.plugin.source.Name, Confidence: h.plugin.source.Confidence,
	})
	return orgent
}

func (h *awards) orgCheckingAccount(e *et.Event, orgent *dbt.Entity) *dbt.Entity {
	o := orgent.Asset.(*oamorg.Organization)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	var accountent *dbt.Entity
	if edges, err := e.Session.DB().OutgoingEdges(ctx, orgent, time.Time{}, "account"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if acc, ok := a.Asset.(*oamacct.Account); ok && acc.Type == oamacct.Checking && acc.Number == "default" {
					accountent = a
					break
				}
			}
		}
	}
	if accountent == nil {
		ent, err := e.Session.DB().CreateAsset(ctx, &oamacct.Account{
			ID:     "org-account:" + o.Name,
			Type:   oamacct.Checking,
			Number: "default",
			Active: o.Active,
		})
		if err != nil || ent == nil {
			return nil
		}
		accountent = ent
	}

	_, _ = e.Session.DB().CreateEntityProperty(ctx, accountent, &general.SourceProperty{
		Source: h.plugin.source.Name, Confidence: h.plugin.source.Confidence,
	})
	_ = h.plugin.createRelation(ctx, e.Session, orgent,
		&general.SimpleRelation{Name: "account"}, accountent, h.plugin.source.Confidence)
	return accountent
}

// winnerMatches reports whether any winner name on a notice is the subject
// organization, compared on normalized text.
func winnerMatches(orgName string, winners []string) bool {
	want := normalizeName(orgName)
	if want == "" {
		return false
	}
	for _, w := range winners {
		if normalizeName(w) == want {
			return true
		}
	}
	return false
}

// flexStrings extracts the string values from a TED field, whatever shape it
// takes: a scalar, a number, a list, or a language-keyed map.
func flexStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}

	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	var num json.Number
	if json.Unmarshal(raw, &num) == nil {
		return []string{num.String()}
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		var out []string
		for _, item := range list {
			out = append(out, flexStrings(item)...)
		}
		return out
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		var out []string
		for _, v := range obj {
			out = append(out, flexStrings(v)...)
		}
		return out
	}
	return nil
}

// flexFloat extracts the first numeric value from a TED field of any shape.
func flexFloat(raw json.RawMessage) float64 {
	for _, s := range flexStrings(raw) {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && v > 0 {
			return v
		}
	}
	return 0
}

func first(ss []string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// normalizeName lowercases a name and collapses runs of non-alphanumeric
// characters to a single space.
func normalizeName(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			space = false
		case !space:
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(b.String())
}
