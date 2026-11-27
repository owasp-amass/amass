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
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
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

// parseTickers maps each company title's name key (semantics.OrgNameKey) to
// its 10-digit CIK. A key that titles of different companies share is left
// out, since it cannot say which company an organization is.
func parseTickers(body []byte) (map[string]string, error) {
	var raw map[string]tickerEntry
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	out := make(map[string]string, len(raw))
	shared := map[string]bool{}
	for _, t := range raw {
		key := semantics.OrgNameKey(t.Title)
		if key == "" || t.CIK == 0 {
			continue
		}

		cik := fmt.Sprintf("%010d", t.CIK)
		if prev, ok := out[key]; ok && prev != cik {
			shared[key] = true
		}
		out[key] = cik
	}
	for key := range shared {
		delete(out, key)
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

	return h.plugin.cikByOrg[semantics.OrgNameKey(name)]
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

	// Every subsidiary goes to the engine; each collector's monitoring TTL
	// keeps a later run from looking the same subsidiaries up again.
	for _, child := range h.storeSubsidiaries(e, orgent, cik, sub) {
		org.DispatchOrg(e, child)
	}
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
	support.AddSource(ctx, e.Session, ident, h.plugin.source)
	_, _ = support.Relate(ctx, e.Session, orgent,
		&general.SimpleRelation{Name: "id"}, ident, h.plugin.source)
}

func (h *filings) storeContact(e *et.Event, orgent *dbt.Entity, cik string, sub *submissions) {
	phone := support.PhoneToOAMPhone(sub.Phone, "", "US")
	loc := businessAddress(&sub.Addresses.Business)
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
	support.AddSource(ctx, e.Session, cr, h.plugin.source)
	if _, err := support.Relate(ctx, e.Session, cr,
		&general.SimpleRelation{Name: "organization"}, orgent, h.plugin.source); err != nil {
		return
	}

	if phone != nil {
		phone.Type = contact.PhoneTypeRegular
		if a, err := e.Session.DB().CreateAsset(ctx, phone); err == nil && a != nil {
			support.AddSource(ctx, e.Session, a, h.plugin.source)
			_, _ = support.Relate(ctx, e.Session, cr,
				&general.SimpleRelation{Name: "phone"}, a, h.plugin.source)
			_ = e.Dispatcher.DispatchEvent(&et.Event{Name: phone.E164, Entity: a, Session: e.Session})
		}
	}
	if loc != nil {
		if a, err := e.Session.DB().CreateAsset(ctx, loc); err == nil && a != nil {
			support.AddSource(ctx, e.Session, a, h.plugin.source)
			_, _ = support.Relate(ctx, e.Session, cr,
				&general.SimpleRelation{Name: "street_address"}, a, h.plugin.source)
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
	if fundent := org.StoreReceivedTransfer(e, orgent, org.ReceivedTransfer{
		ID: "secformd:" + accession, Reference: accession, Amount: amount, Date: date,
	}, h.plugin.source); fundent != nil {
		org.DispatchTransfers(e, fundent)
	}
}

// businessAddress builds a StreetAddress in standard form from a filer's
// business address, or nil when it has no city or its country is unknown.
// EDGAR's stateOrCountry is a US state's code for a US address and an EDGAR
// code otherwise, so only US addresses have a known country.
func businessAddress(a *address) *contact.StreetAddress {
	if !support.IsSubdivision("US", a.StateOrCountry) {
		return nil
	}
	return support.NormalizeStreetAddress(&contact.StreetAddress{
		Address:    strings.TrimSpace(a.Street1 + " " + a.Street2),
		City:       a.City,
		Province:   a.StateOrCountry,
		PostalCode: a.ZipCode,
		Country:    "US",
	})
}
