// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ocds

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

type publisher struct {
	Key      string `json:"key"`
	Country  string `json:"country"`
	Name     string `json:"name"`
	QueryURL string `json:"query_url"`
	Enabled  bool   `json:"enabled"`
}

var loadPublishers = sync.OnceValue(func() []publisher {
	var c struct {
		Publishers []publisher `json:"publishers"`
	}
	if err := json.Unmarshal(semantics.File("ocds_publishers.json"), &c); err != nil {
		panic("ocds_publishers.json: " + err.Error())
	}
	return c.Publishers
})

// --- OCDS schema (release and record packages) ---

type ocdsValue struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

type ocdsParty struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

type ocdsRelease struct {
	OCID  string `json:"ocid"`
	Date  string `json:"date"`
	Buyer struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"buyer"`
	Parties []ocdsParty `json:"parties"`
	Awards  []struct {
		ID        string    `json:"id"`
		Date      string    `json:"date"`
		Value     ocdsValue `json:"value"`
		Suppliers []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"suppliers"`
	} `json:"awards"`
}

type ocdsPackage struct {
	Releases []ocdsRelease `json:"releases"`
	Records  []struct {
		CompiledRelease ocdsRelease `json:"compiledRelease"`
	} `json:"records"`
}

// award is one supplier's award, normalized from an OCDS package.
type award struct {
	ocid, id, supplier, buyer, currency, date string
	amount                                    float64
}

// parseOCDS reads an OCDS release or record package into awards, one per
// supplier named on each award.
func parseOCDS(body []byte) ([]award, error) {
	var p ocdsPackage
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}

	releases := p.Releases
	for _, r := range p.Records {
		releases = append(releases, r.CompiledRelease)
	}

	var out []award
	for _, r := range releases {
		buyer := r.Buyer.Name
		if buyer == "" {
			buyer = roleName(r.Parties, "buyer")
		}
		for _, a := range r.Awards {
			date := a.Date
			if date == "" {
				date = r.Date
			}
			for _, s := range a.Suppliers {
				if strings.TrimSpace(s.Name) == "" {
					continue
				}
				out = append(out, award{
					ocid: r.OCID, id: a.ID, supplier: s.Name, buyer: buyer,
					amount: a.Value.Amount, currency: a.Value.Currency, date: date,
				})
			}
		}
	}
	return out, nil
}

// roleName returns the name of the first party holding a role.
func roleName(parties []ocdsParty, role string) string {
	for _, p := range parties {
		for _, r := range p.Roles {
			if strings.EqualFold(r, role) {
				return p.Name
			}
		}
	}
	return ""
}

func (h *handler) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return nil
	}

	for _, pub := range loadPublishers() {
		if !pub.Enabled || !strings.Contains(pub.QueryURL, "{supplier}") {
			continue
		}

		src := &et.Source{Name: h.plugin.source.Name + ":" + pub.Key, Confidence: h.plugin.source.Confidence}
		since, err := support.TTLStartTime(e.Session.Config(),
			string(oam.Organization), string(oam.FundsTransfer), h.plugin.name)
		if err != nil {
			return err
		}
		if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
			continue
		}
		h.query(e, e.Entity, o.Name, pub)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}
	return nil
}

func (h *handler) query(e *et.Event, orgent *dbt.Entity, name string, pub publisher) {
	u := strings.ReplaceAll(pub.QueryURL, "{supplier}", url.QueryEscape(name))

	_ = support.WaitLimit(e.Session.Ctx(), h.plugin.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 45*time.Second)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	e.Session.NetSem().Release()
	cancel()
	if err != nil || resp.StatusCode != 200 || resp.Body == "" {
		if err != nil {
			e.Session.Log().Error(fmt.Sprintf("OCDS %s query for %s failed: %s", pub.Key, name, err),
				slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		}
		return
	}

	awards, err := parseOCDS([]byte(resp.Body))
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("failed to parse OCDS %s for %s: %s", pub.Key, name, err),
			slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}

	seen := map[string]bool{}
	for i := range awards {
		a := &awards[i]
		if !supplierMatches(name, a.supplier) {
			continue
		}
		id := "ocds:" + a.ocid + ":" + a.id
		if seen[id] {
			continue
		}
		seen[id] = true
		h.store(e, orgent, a, id)
	}
}

func (h *handler) store(e *et.Event, orgent *dbt.Entity, a *award, id string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	orgacc := h.orgCheckingAccount(e, orgent)
	if orgacc == nil {
		return
	}

	currency := a.currency
	if currency == "" {
		currency = "USD"
	}
	fundent, err := e.Session.DB().CreateAsset(ctx, &oamfin.FundsTransfer{
		ID:              id,
		Amount:          a.amount,
		Currency:        currency,
		ReferenceNumber: a.ocid + ":" + a.id,
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
	if buyer := h.buyerOrg(e, a.buyer); buyer != nil {
		_ = h.plugin.createRelation(ctx, e.Session, fundent,
			&general.SimpleRelation{Name: "third_party"}, buyer, h.plugin.source.Confidence)
	}

	_ = e.Dispatcher.DispatchEvent(&et.Event{Name: fmt.Sprintf("%f:%s", a.amount, id), Entity: fundent, Session: e.Session})
}

func (h *handler) buyerOrg(e *et.Event, name string) *dbt.Entity {
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

func (h *handler) orgCheckingAccount(e *et.Event, orgent *dbt.Entity) *dbt.Entity {
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

// supplierMatches reports whether an OCDS supplier name is the subject
// organization, compared on normalized text.
func supplierMatches(orgName, supplier string) bool {
	a, b := normalizeName(orgName), normalizeName(supplier)
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.HasPrefix(b, a+" ") || strings.HasPrefix(a, b+" ")
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
