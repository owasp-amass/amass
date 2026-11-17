// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package propublica

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	"github.com/owasp-amass/open-asset-model/contact"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// maxFilings bounds how many recent filings become FundsTransfers.
const maxFilings = 5

type pubSearch struct {
	Organizations []struct {
		EIN  int64  `json:"ein"`
		Name string `json:"name"`
	} `json:"organizations"`
}

type pubOrg struct {
	Organization struct {
		EIN     int64  `json:"ein"`
		StrEIN  string `json:"strein"`
		Name    string `json:"name"`
		Address string `json:"address"`
		City    string `json:"city"`
		State   string `json:"state"`
		Zipcode string `json:"zipcode"`
	} `json:"organization"`
	Filings []map[string]json.RawMessage `json:"filings_with_data"`
}

func parseSearch(body []byte) (*pubSearch, error) {
	var s pubSearch
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func parseOrg(body []byte) (*pubOrg, error) {
	var o pubOrg
	if err := json.Unmarshal(body, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

func (h *filings) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.Identifier), h.plugin.name)
	if err != nil {
		return err
	}
	src := &et.Source{Name: h.name, Confidence: h.plugin.source.Confidence}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		return nil
	}

	if ein := h.resolve(e, o.Name); ein != "" {
		h.collect(e, e.Entity, ein)
	}
	support.MarkAssetMonitored(e.Session, e.Entity, src)
	return nil
}

// resolve finds the EIN of a nonprofit whose name matches the organization.
func (h *filings) resolve(e *et.Event, name string) string {
	body, err := h.get(e, h.plugin.api+"/search.json?q="+url.QueryEscape(name))
	if err != nil {
		return ""
	}
	res, err := parseSearch([]byte(body))
	if err != nil {
		return ""
	}
	want := normalizeName(name)
	for _, o := range res.Organizations {
		if o.EIN != 0 && normalizeName(o.Name) == want {
			return strconv.FormatInt(o.EIN, 10)
		}
	}
	return ""
}

func (h *filings) collect(e *et.Event, orgent *dbt.Entity, ein string) {
	body, err := h.get(e, fmt.Sprintf("%s/organizations/%s.json", h.plugin.api, ein))
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("ProPublica org %s failed: %s", ein, err),
			slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}
	org, err := parseOrg([]byte(body))
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("failed to parse ProPublica org %s: %s", ein, err),
			slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}

	h.storeEIN(e, orgent, org)
	h.storeContact(e, orgent, org)
	h.storeFilings(e, orgent, org)
}

func (h *filings) get(e *et.Event, u string) (string, error) {
	_ = support.WaitLimit(e.Session.Ctx(), h.plugin.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	e.Session.NetSem().Release()
	cancel()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 || resp.Body == "" {
		return "", fmt.Errorf("status %s", resp.Status)
	}
	return resp.Body, nil
}

func (h *filings) storeEIN(e *et.Event, orgent *dbt.Entity, o *pubOrg) {
	strein := o.Organization.StrEIN
	if strein == "" {
		return
	}
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	ident, err := e.Session.DB().CreateAsset(ctx, &general.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", EINIdentifier, strein),
		ID:       strein,
		Type:     EINIdentifier,
	})
	if err != nil || ident == nil {
		return
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, ident, &general.SourceProperty{
		Source: h.plugin.source.Name, Confidence: h.plugin.source.Confidence,
	})
	_ = h.plugin.createRelation(ctx, e.Session, orgent,
		&general.SimpleRelation{Name: "id"}, ident, h.plugin.source.Confidence)
}

func (h *filings) storeContact(e *et.Event, orgent *dbt.Entity, o *pubOrg) {
	a := o.Organization
	if strings.TrimSpace(a.Address) == "" && a.City == "" {
		return
	}
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	cr, err := e.Session.DB().CreateAsset(ctx, &contact.ContactRecord{
		DiscoveredAt: fmt.Sprintf("https://projects.propublica.org/nonprofits/organizations/%d", a.EIN),
	})
	if err != nil || cr == nil {
		return
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, cr, &general.SourceProperty{
		Source: h.plugin.source.Name, Confidence: h.plugin.source.Confidence,
	})
	if err := h.plugin.createRelation(ctx, e.Session, cr,
		&general.SimpleRelation{Name: "organization"}, orgent, h.plugin.source.Confidence); err != nil {
		return
	}
	loc := &contact.Location{Address: a.Address, City: a.City, Province: a.State, PostalCode: a.Zipcode}
	if l, err := e.Session.DB().CreateAsset(ctx, loc); err == nil && l != nil {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, l, &general.SourceProperty{
			Source: h.plugin.source.Name, Confidence: h.plugin.source.Confidence,
		})
		_ = h.plugin.createRelation(ctx, e.Session, cr,
			&general.SimpleRelation{Name: "location"}, l, h.plugin.source.Confidence)
	}
}

// storeFilings records contributions and grants received as FundsTransfers,
// when a filing reports that figure (totcntrbgfts). The amount is an aggregate
// with no named funder, so no funding party is attached.
func (h *filings) storeFilings(e *et.Event, orgent *dbt.Entity, o *pubOrg) {
	strein := o.Organization.StrEIN
	if strein == "" || len(o.Filings) == 0 {
		return
	}

	var orgacc *dbt.Entity
	for i, f := range o.Filings {
		if i >= maxFilings {
			break
		}
		amount := flexNum(f["totcntrbgfts"])
		if amount <= 0 {
			continue
		}
		year := flexStr(f["tax_prd_yr"])

		if orgacc == nil {
			if orgacc = h.orgCheckingAccount(e, orgent); orgacc == nil {
				return
			}
		}

		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
		fundent, err := e.Session.DB().CreateAsset(ctx, &oamfin.FundsTransfer{
			ID:              "irs990:" + strein + ":" + year,
			Amount:          amount,
			Currency:        "USD",
			ReferenceNumber: strein + ":" + year,
			ExchangeDate:    year,
		})
		if err == nil && fundent != nil {
			_, _ = e.Session.DB().CreateEntityProperty(ctx, fundent, &general.SourceProperty{
				Source: h.plugin.source.Name, Confidence: h.plugin.source.Confidence,
			})
			_ = h.plugin.createRelation(ctx, e.Session, fundent,
				&general.SimpleRelation{Name: "recipient"}, orgacc, h.plugin.source.Confidence)
		}
		cancel()
	}
}

func (h *filings) orgCheckingAccount(e *et.Event, orgent *dbt.Entity) *dbt.Entity {
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
			ID: "org-account:" + o.Name, Type: oamacct.Checking, Number: "default", Active: o.Active,
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

// flexStr renders a JSON value that may be a string or a number as a string.
func flexStr(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

// flexNum parses a JSON value that may be a number or a numeric string.
func flexNum(raw json.RawMessage) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(flexStr(raw)), 64)
	if err != nil {
		return 0
	}
	return v
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
