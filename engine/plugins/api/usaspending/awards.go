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
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// awardTypeGroups are queried one at a time: the API rejects a request that
// mixes award types from different categories.
var awardTypeGroups = [][]string{
	{"A", "B", "C", "D"},     // contracts
	{"02", "03", "04", "05"}, // grants
	{"06", "10"},             // direct payments
	{"07", "08"},             // loans
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
	Amount        float64 `json:"Award Amount"`
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

	// Keyless but opt-in: run only when the user lists this source in the
	// data-source configuration. A non-US organization is simply never enabled
	// for it, and the plugin does no work.
	if ds := e.Session.Config().GetDataSourceConfig(h.plugin.name); ds == nil {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.FundsTransfer), h.plugin.name)
	if err != nil {
		return err
	}

	src := &et.Source{Name: h.name, Confidence: h.plugin.source.Confidence}
	var fundents []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		fundents = h.lookup(e, e.Entity, since)
	} else {
		fundents = h.query(e, e.Entity, o.Name)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if len(fundents) > 0 {
		h.process(e, fundents)
	}
	return nil
}

func (h *awards) query(e *et.Event, orgent *dbt.Entity, name string) []*dbt.Entity {
	var fundents []*dbt.Entity
	seen := map[string]bool{}

	for _, codes := range awardTypeGroups {
		for page := 1; page <= awardsMaxPage; page++ {
			body, err := h.requestPage(e, name, codes, page)
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
				if !recipientMatches(name, a.RecipientName) {
					continue
				}
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

	return fundents
}

// requestPage posts one page of a spending_by_award query for an award-type
// group and returns the response body.
func (h *awards) requestPage(e *et.Event, name string, codes []string, page int) (string, error) {
	type filters struct {
		RecipientSearchText []string `json:"recipient_search_text"`
		AwardTypeCodes      []string `json:"award_type_codes"`
	}
	req := struct {
		Filters filters  `json:"filters"`
		Fields  []string `json:"fields"`
		Page    int      `json:"page"`
		Limit   int      `json:"limit"`
		Sort    string   `json:"sort"`
		Order   string   `json:"order"`
	}{
		Filters: filters{RecipientSearchText: []string{name}, AwardTypeCodes: codes},
		Fields:  []string{"Award ID", "Recipient Name", "Award Amount", "Awarding Agency", "Start Date"},
		Page:    page,
		Limit:   awardsPerPage,
		Sort:    "Award Amount",
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
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	orgacc := h.orgCheckingAccount(e, orgent)
	if orgacc == nil {
		return nil
	}

	f := &oamfin.FundsTransfer{
		ID:              id,
		Amount:          a.Amount,
		Currency:        "USD",
		ReferenceNumber: a.AwardID,
		ExchangeDate:    a.StartDate,
	}
	fundent, err := e.Session.DB().CreateAsset(ctx, f)
	if err != nil || fundent == nil {
		msg := fmt.Sprintf("failed to create the FundsTransfer asset for %s: %s", id, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return nil
	}

	if _, err := e.Session.DB().CreateEntityProperty(ctx, fundent, &oamgen.SourceProperty{
		Source:     h.plugin.source.Name,
		Confidence: h.plugin.source.Confidence,
	}); err != nil {
		msg := fmt.Sprintf("failed to create the FundsTransfer source property for %s: %s", id, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return nil
	}

	if err := h.plugin.createRelation(ctx, e.Session, fundent,
		oamgen.SimpleRelation{Name: "recipient"}, orgacc, h.plugin.source.Confidence); err != nil {
		msg := fmt.Sprintf("failed to create the recipient relation for %s: %s", id, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return nil
	}

	// The awarding agency is the funding party, surfaced by the funding lens.
	if agency := h.agencyOrg(e, a.Agency); agency != nil {
		if err := h.plugin.createRelation(ctx, e.Session, fundent,
			oamgen.SimpleRelation{Name: "third_party"}, agency, h.plugin.source.Confidence); err != nil {
			msg := fmt.Sprintf("failed to create the third_party relation for %s: %s", id, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		}
	}

	return fundent
}

// orgCheckingAccount returns the organization's default checking account,
// creating it and the Organization --account--> Account edge when absent.
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
			msg := fmt.Sprintf("failed to create the Account asset for %s: %s", o.Name, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
			return nil
		}
		accountent = ent
	}

	if _, err := e.Session.DB().CreateEntityProperty(ctx, accountent, &oamgen.SourceProperty{
		Source:     h.plugin.source.Name,
		Confidence: h.plugin.source.Confidence,
	}); err != nil {
		msg := fmt.Sprintf("failed to create the Account source property for %s: %s", o.Name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return nil
	}

	if err := h.plugin.createRelation(ctx, e.Session, orgent,
		oamgen.SimpleRelation{Name: "account"}, accountent, h.plugin.source.Confidence); err != nil {
		msg := fmt.Sprintf("failed to create the account relation for %s: %s", o.Name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
	}

	return accountent
}

// agencyOrg returns the awarding agency as an Organization, creating it when
// absent, or nil when the award named no agency.
func (h *awards) agencyOrg(e *et.Event, name string) *dbt.Entity {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}

	orgent, err := org.CreateOrgAsset(e.Session, nil, nil, &oamorg.Organization{Name: name}, h.plugin.source)
	if err != nil || orgent == nil {
		msg := fmt.Sprintf("failed to create the agency Organization %s: %s", name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()
	if _, err := e.Session.DB().CreateEntityProperty(ctx, orgent, &oamgen.SourceProperty{
		Source:     h.plugin.source.Name,
		Confidence: h.plugin.source.Confidence,
	}); err != nil {
		msg := fmt.Sprintf("failed to create the agency source property for %s: %s", name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
	}

	return orgent
}

func (h *awards) lookup(e *et.Event, orgent *dbt.Entity, since time.Time) []*dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	var accountents []*dbt.Entity
	if edges, err := e.Session.DB().OutgoingEdges(ctx, orgent, since, "account"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.DB().FindEdgeTags(ctx, edge, since, h.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if acc, ok := a.Asset.(*oamacct.Account); ok && acc.Type == oamacct.Checking && acc.Number == "default" {
					accountents = append(accountents, a)
				}
			}
		}
	}

	var fundents []*dbt.Entity
	for _, ent := range accountents {
		if edges, err := e.Session.DB().IncomingEdges(ctx, ent, since, "recipient"); err == nil {
			for _, edge := range edges {
				if tags, err := e.Session.DB().FindEdgeTags(ctx, edge, since, h.plugin.source.Name); err != nil || len(tags) == 0 {
					continue
				}
				if a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*oamfin.FundsTransfer); ok {
						fundents = append(fundents, a)
					}
				}
			}
		}
	}

	return fundents
}

func (h *awards) process(e *et.Event, fundents []*dbt.Entity) {
	for _, fund := range fundents {
		f := fund.Asset.(*oamfin.FundsTransfer)
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fmt.Sprintf("%f:%s", f.Amount, f.ID),
			Entity:  fund,
			Session: e.Session,
		})
	}
}

// recipientMatches reports whether a USAspending recipient name is the same
// organization as the one enumerated, comparing on normalized text so casing
// and punctuation do not matter while a genuinely different recipient is not
// taken for a match.
func recipientMatches(orgName, recipient string) bool {
	a, b := normalizeOrg(orgName), normalizeOrg(recipient)
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.HasPrefix(b, a+" ") || strings.HasPrefix(a, b+" ")
}

// normalizeOrg lowercases a name and collapses every run of non-alphanumeric
// characters to a single space.
func normalizeOrg(s string) string {
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
