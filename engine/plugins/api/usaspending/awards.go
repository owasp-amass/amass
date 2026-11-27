// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usaspending

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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

// awardGroup is one category of award types with the field that holds its
// amount. The groups are queried one at a time: the API rejects a request
// that mixes award types from different categories, and loans have a loan
// value instead of an award amount (asking for "Award Amount" on loans is
// rejected).
type awardGroup struct {
	codes  []string
	amount string
	date   string
}

var awardTypeGroups = []awardGroup{
	{codes: []string{"A", "B", "C", "D"}, amount: "Award Amount", date: "Start Date"},     // contracts
	{codes: []string{"02", "03", "04", "05"}, amount: "Award Amount", date: "Start Date"}, // grants
	{codes: []string{"06", "10"}, amount: "Award Amount", date: "Start Date"},             // direct payments
	{codes: []string{"07", "08"}, amount: "Loan Value"},                                   // loans
}

const (
	awardsPerPage = 100
	awardsMaxPage = 3
)

// award is one row of a spending_by_award result. The field names are the
// display names the API returns for the requested fields.
type award struct {
	AwardID       string  `json:"Award ID"`
	RecipientName string  `json:"Recipient Name"`
	RecipientUEI  string  `json:"Recipient UEI"`
	Amount        float64 `json:"Award Amount"`
	LoanValue     float64 `json:"Loan Value"`
	Agency        string  `json:"Awarding Agency"`
	StartDate     string  `json:"Start Date"`
	GeneratedID   string  `json:"generated_internal_id"`
}

type awardsPage struct {
	Results      []award `json:"results"`
	PageMetadata struct {
		HasNext bool `json:"hasNext"`
	} `json:"page_metadata"`
}

// parseAwards reads one page of spending_by_award results, returning the rows
// and whether another page follows.
func parseAwards(body []byte) ([]award, bool, error) {
	var p awardsPage
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, false, err
	}
	return p.Results, p.PageMetadata.HasNext, nil
}

// transferID is the stable FundsTransfer ID for an award.
func (a *award) transferID() string {
	if a.GeneratedID != "" {
		return a.GeneratedID
	}
	if a.AwardID != "" {
		return "usaspending:" + a.AwardID
	}
	return ""
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
	var fundents []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		fundents = org.OrgTransfersReceived(e.Session, e.Entity, since, h.plugin.source)
	} else {
		fundents = h.query(e, e.Entity, o.Name)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if len(fundents) > 0 {
		org.DispatchTransfers(e, fundents...)
	}
	return nil
}

func (h *awards) query(e *et.Event, orgent *dbt.Entity, name string) []*dbt.Entity {
	var fundents []*dbt.Entity
	var ueis []string
	seen := map[string]bool{}

	for _, group := range awardTypeGroups {
		for page := 1; page <= awardsMaxPage; page++ {
			body, err := h.requestPage(e, name, group, page)
			if err != nil {
				msg := fmt.Sprintf("failed to obtain awards for %s: %s", name, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
				break
			}

			rows, hasNext, err := parseAwards([]byte(body))
			if err != nil {
				msg := fmt.Sprintf("failed to parse awards for %s: %s", name, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
				break
			}

			for i := range rows {
				a := &rows[i]
				// Guard against same-name recipients that are not this org.
				if !semantics.SameOrgName(name, a.RecipientName) {
					continue
				}
				ueis = append(ueis, a.RecipientUEI)
				id := a.transferID()
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				if ent := h.store(e, orgent, a, id); ent != nil {
					fundents = append(fundents, ent)
				}
			}

			if !hasNext {
				break
			}
		}
	}

	// the recipient's Unique Entity ID identifies it for duplicate detection,
	// when every matched award names the same one
	org.StoreUnambiguousIdentifier(e.Session, orgent, org.UEIIdentifier, ueis, h.plugin.source)
	return fundents
}

// requestPage posts one page of a spending_by_award query for an award-type
// group and returns the response body.
func (h *awards) requestPage(e *et.Event, name string, group awardGroup, page int) (string, error) {
	type filters struct {
		RecipientSearchText []string `json:"recipient_search_text"`
		AwardTypeCodes      []string `json:"award_type_codes"`
	}
	fields := []string{"Award ID", "Recipient Name", "Recipient UEI", group.amount, "Awarding Agency"}
	if group.date != "" {
		fields = append(fields, group.date)
	}
	req := struct {
		Filters filters  `json:"filters"`
		Fields  []string `json:"fields"`
		Page    int      `json:"page"`
		Limit   int      `json:"limit"`
		Sort    string   `json:"sort"`
		Order   string   `json:"order"`
	}{
		Filters: filters{RecipientSearchText: []string{name}, AwardTypeCodes: group.codes},
		Fields:  fields,
		Page:    page,
		Limit:   awardsPerPage,
		Sort:    group.amount,
		Order:   "desc",
	}

	bodyJSON, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	_ = support.WaitLimit(e.Session.Ctx(), h.plugin.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    h.plugin.api + "/search/spending_by_award/",
		Method: "POST",
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}},
		Body:   string(bodyJSON),
	})
	e.Session.NetSem().Release()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %s", resp.Status)
	}
	if resp.Body == "" {
		return "", errors.New("empty body")
	}
	return resp.Body, nil
}

func (h *awards) store(e *et.Event, orgent *dbt.Entity, a *award, id string) *dbt.Entity {
	// The awarding agency is the funding party, surfaced by the funding lens.
	// An award with no positive amount (a deobligation or modification) is
	// skipped.
	return org.StoreReceivedTransfer(e, orgent, org.ReceivedTransfer{
		ID: id, Reference: a.AwardID, Amount: max(a.Amount, a.LoanValue), Date: a.StartDate, Funder: a.Agency,
	}, h.plugin.source)
}
