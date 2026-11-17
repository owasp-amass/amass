// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"context"
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
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// grant is one award normalized across the three APIs before it is stored.
type grant struct {
	id, date, agency, recipient string
	amount                      float64
}

func (h *source) get(e *et.Event, u string) (string, error) {
	return h.request(e, &amasshttp.Request{URL: u})
}

func (h *source) postJSON(e *et.Event, u, body string) (string, error) {
	return h.request(e, &amasshttp.Request{
		URL:    u,
		Method: "POST",
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}},
		Body:   body,
	})
}

func (h *source) request(e *et.Event, r *amasshttp.Request) (string, error) {
	_ = support.WaitLimit(e.Session.Ctx(), h.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, r)
	e.Session.NetSem().Release()
	cancel()
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

// store writes a matched grant as a FundsTransfer received by the organization,
// with the funding agency as the third_party funder.
func (h *source) store(e *et.Event, orgent *dbt.Entity, g *grant) *dbt.Entity {
	if g.id == "" {
		return nil
	}
	// The Asset Database rejects a FundsTransfer with a non-positive amount,
	// so skip a grant we could find no amount for rather than logging a
	// storage error for every one.
	if g.amount <= 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	orgacc := h.orgCheckingAccount(e, orgent)
	if orgacc == nil {
		return nil
	}

	fundent, err := e.Session.DB().CreateAsset(ctx, &oamfin.FundsTransfer{
		ID:              g.id,
		Amount:          g.amount,
		Currency:        "USD",
		ReferenceNumber: g.id,
		ExchangeDate:    g.date,
	})
	if err != nil || fundent == nil {
		msg := fmt.Sprintf("failed to create the FundsTransfer for %s: %s", g.id, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.name))
		return nil
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, fundent, &general.SourceProperty{
		Source: h.src.Name, Confidence: h.src.Confidence,
	})
	if err := h.createRelation(ctx, e.Session, fundent,
		&general.SimpleRelation{Name: "recipient"}, orgacc, h.src); err != nil {
		return nil
	}
	if agency := h.agencyOrg(e, g.agency); agency != nil {
		_ = h.createRelation(ctx, e.Session, fundent,
			&general.SimpleRelation{Name: "third_party"}, agency, h.src)
	}

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name: fmt.Sprintf("%f:%s", g.amount, g.id), Entity: fundent, Session: e.Session,
	})
	return fundent
}

func (h *source) orgCheckingAccount(e *et.Event, orgent *dbt.Entity) *dbt.Entity {
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
		Source: h.src.Name, Confidence: h.src.Confidence,
	})
	_ = h.createRelation(ctx, e.Session, orgent,
		&general.SimpleRelation{Name: "account"}, accountent, h.src)
	return accountent
}

func (h *source) agencyOrg(e *et.Event, name string) *dbt.Entity {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	orgent, err := org.CreateOrgAsset(e.Session, nil, nil, &oamorg.Organization{Name: name}, h.src)
	if err != nil || orgent == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()
	_, _ = e.Session.DB().CreateEntityProperty(ctx, orgent, &general.SourceProperty{
		Source: h.src.Name, Confidence: h.src.Confidence,
	})
	return orgent
}

// recipientMatches reports whether an API recipient name is the subject
// organization, compared on normalized text.
func recipientMatches(orgName, recipient string) bool {
	a, b := normalizeName(orgName), normalizeName(recipient)
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
