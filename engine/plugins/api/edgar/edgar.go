// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package edgar

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
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

// maxFormD bounds how many recent Form D filings are turned into FundsTransfers.
const maxFormD = 10

// tickerEntry is one row of SEC's company_tickers.json.
type tickerEntry struct {
	CIK    int64  `json:"cik_str"`
	Ticker string `json:"ticker"`
	Title  string `json:"title"`
}

// parseTickers maps each company title to its 10-digit CIK.
func parseTickers(body []byte) (map[string]string, error) {
	var raw map[string]tickerEntry
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for _, t := range raw {
		if t.Title == "" || t.CIK == 0 {
			continue
		}
		out[normalizeName(t.Title)] = fmt.Sprintf("%010d", t.CIK)
	}
	return out, nil
}

// submissions is the subset of data.sec.gov/submissions we read.
type submissions struct {
	CIK       string `json:"cik"`
	Name      string `json:"name"`
	Phone     string `json:"phone"`
	Addresses struct {
		Business address `json:"business"`
	} `json:"addresses"`
	Filings struct {
		Recent struct {
			AccessionNumber []string `json:"accessionNumber"`
			Form            []string `json:"form"`
			FilingDate      []string `json:"filingDate"`
			PrimaryDocument []string `json:"primaryDocument"`
		} `json:"recent"`
	} `json:"filings"`
}

type address struct {
	Street1        string `json:"street1"`
	Street2        string `json:"street2"`
	City           string `json:"city"`
	StateOrCountry string `json:"stateOrCountry"`
	ZipCode        string `json:"zipCode"`
}

func parseSubmissions(body []byte) (*submissions, error) {
	var s submissions
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// formD is the Form D exempt-offering amounts.
type formD struct {
	XMLName      xml.Name `xml:"edgarSubmission"`
	OfferingData struct {
		OfferingSalesAmounts struct {
			TotalOfferingAmount string `xml:"totalOfferingAmount"`
			TotalAmountSold     string `xml:"totalAmountSold"`
		} `xml:"offeringSalesAmounts"`
	} `xml:"offeringData"`
}

// parseFormDAmount returns the dollars sold in a Form D (falling back to the
// total offering amount), or 0 when the filing names no definite amount.
func parseFormDAmount(body []byte) float64 {
	var d formD
	if xml.Unmarshal(body, &d) != nil {
		return 0
	}
	for _, s := range []string{d.OfferingData.OfferingSalesAmounts.TotalAmountSold,
		d.OfferingData.OfferingSalesAmounts.TotalOfferingAmount} {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && v > 0 {
			return v
		}
	}
	return 0
}

func (h *filings) check(e *et.Event) error {
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

	// A non-US filer resolves to no CIK; nothing is stored.
	if cik := h.cik(e, o.Name); cik != "" {
		h.collect(e, e.Entity, cik)
	}
	support.MarkAssetMonitored(e.Session, e.Entity, src)
	return nil
}

// cik resolves an organization name to its SEC CIK using the ticker catalog,
// fetched and cached on first use.
func (h *filings) cik(e *et.Event, name string) string {
	h.plugin.mu.Lock()
	defer h.plugin.mu.Unlock()

	if h.plugin.cikByOrg == nil {
		body, err := h.get(e, h.plugin.www+"/files/company_tickers.json")
		if err != nil {
			return "" // not cached, so another organization retries the fetch
		}
		m, err := parseTickers([]byte(body))
		if err != nil {
			return ""
		}
		h.plugin.cikByOrg = m
	}

	return h.plugin.cikByOrg[normalizeName(name)]
}

func (h *filings) collect(e *et.Event, orgent *dbt.Entity, cik string) {
	body, err := h.get(e, fmt.Sprintf("%s/submissions/CIK%s.json", h.plugin.api, cik))
	if err != nil {
		msg := fmt.Sprintf("failed to obtain submissions for CIK%s: %s", cik, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}
	sub, err := parseSubmissions([]byte(body))
	if err != nil {
		msg := fmt.Sprintf("failed to parse submissions for CIK%s: %s", cik, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}

	h.storeCIK(e, orgent, cik)
	h.storeContact(e, orgent, cik, sub)
	h.storeFormD(e, orgent, cik, sub)
}

// get performs a rate-limited GET with the SEC-required User-Agent.
func (h *filings) get(e *et.Event, u string) (string, error) {
	_ = support.WaitLimit(e.Session.Ctx(), h.plugin.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    u,
		Header: amasshttp.Header{"User-Agent": {userAgent}},
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

func (h *filings) storeCIK(e *et.Event, orgent *dbt.Entity, cik string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	ident, err := e.Session.DB().CreateAsset(ctx, &general.Identifier{
		UniqueID: fmt.Sprintf("%s:%s", CIKIdentifier, cik),
		ID:       cik,
		Type:     CIKIdentifier,
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

func (h *filings) storeContact(e *et.Event, orgent *dbt.Entity, cik string, sub *submissions) {
	phone := support.PhoneToOAMPhone(sub.Phone, "", "US")
	loc := businessLocation(&sub.Addresses.Business)
	if phone == nil && loc == nil {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	cr, err := e.Session.DB().CreateAsset(ctx, &contact.ContactRecord{
		DiscoveredAt: fmt.Sprintf("%s/cgi-bin/browse-edgar?action=getcompany&CIK=%s", h.plugin.www, cik),
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

	if phone != nil {
		phone.Type = contact.PhoneTypeRegular
		if a, err := e.Session.DB().CreateAsset(ctx, phone); err == nil && a != nil {
			_, _ = e.Session.DB().CreateEntityProperty(ctx, a, &general.SourceProperty{
				Source: h.plugin.source.Name, Confidence: h.plugin.source.Confidence,
			})
			_ = h.plugin.createRelation(ctx, e.Session, cr,
				&general.SimpleRelation{Name: "phone"}, a, h.plugin.source.Confidence)
			_ = e.Dispatcher.DispatchEvent(&et.Event{Name: phone.E164, Entity: a, Session: e.Session})
		}
	}
	if loc != nil {
		if a, err := e.Session.DB().CreateAsset(ctx, loc); err == nil && a != nil {
			_, _ = e.Session.DB().CreateEntityProperty(ctx, a, &general.SourceProperty{
				Source: h.plugin.source.Name, Confidence: h.plugin.source.Confidence,
			})
			_ = h.plugin.createRelation(ctx, e.Session, cr,
				&general.SimpleRelation{Name: "location"}, a, h.plugin.source.Confidence)
		}
	}
}

func (h *filings) storeFormD(e *et.Event, orgent *dbt.Entity, cik string, sub *submissions) {
	r := sub.Filings.Recent
	n := len(r.Form)
	if len(r.AccessionNumber) < n || len(r.FilingDate) < n || len(r.PrimaryDocument) < n {
		return // parallel arrays must align
	}

	cikDir := strings.TrimLeft(cik, "0")
	count := 0
	for i := 0; i < n && count < maxFormD; i++ {
		if r.Form[i] != "D" {
			continue
		}
		count++

		accession := r.AccessionNumber[i]
		doc := r.PrimaryDocument[i]
		if accession == "" || doc == "" {
			continue
		}
		u := fmt.Sprintf("%s/Archives/edgar/data/%s/%s/%s", h.plugin.www, cikDir,
			strings.ReplaceAll(accession, "-", ""), doc)

		body, err := h.get(e, u)
		if err != nil {
			continue
		}
		amount := parseFormDAmount([]byte(body))
		if amount <= 0 {
			continue
		}
		h.storeTransfer(e, orgent, accession, r.FilingDate[i], amount)
	}
}

func (h *filings) storeTransfer(e *et.Event, orgent *dbt.Entity, accession, date string, amount float64) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	orgacc := h.orgCheckingAccount(e, orgent)
	if orgacc == nil {
		return
	}

	fundent, err := e.Session.DB().CreateAsset(ctx, &oamfin.FundsTransfer{
		ID:              "secformd:" + accession,
		Amount:          amount,
		Currency:        "USD",
		ReferenceNumber: accession,
		ExchangeDate:    date,
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
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name: fmt.Sprintf("%f:secformd:%s", amount, accession), Entity: fundent, Session: e.Session,
	})
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

// businessLocation builds a Location from a filer's business address, or nil
// when the address is empty.
func businessLocation(a *address) *contact.Location {
	street := strings.TrimSpace(a.Street1 + " " + a.Street2)
	if street == "" && a.City == "" {
		return nil
	}
	return &contact.Location{
		Address:    street,
		City:       a.City,
		Province:   a.StateOrCountry,
		PostalCode: a.ZipCode,
	}
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
