// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// OrgCheckingAccount returns the organization's default checking account, the
// account the funds transfers collectors find (awards, grants, contracts,
// funding rounds, filings) are sent to or from, creating it when the
// organization has none. src is recorded as a source of the account and of
// the organization's account edge. It returns nil on a failure.
func OrgCheckingAccount(sess et.Session, orgent *dbt.Entity, src *et.Source) *dbt.Entity {
	o, ok := orgent.Asset.(*oamorg.Organization)
	if !ok {
		return nil
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	var accountent *dbt.Entity
	if accts := checkingAccounts(ctx, sess, orgent, time.Time{}, nil); len(accts) > 0 {
		accountent = accts[0]
	} else {
		ent, err := sess.DB().CreateAsset(ctx, &oamacct.Account{
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

	support.AddSource(ctx, sess, accountent, src)

	if _, err := support.Relate(ctx, sess, orgent, &oamgen.SimpleRelation{Name: "account"}, accountent, src); err != nil {
		return nil
	}
	return accountent
}

// ReceivedTransfer is a funds transfer an organization received, as a
// funding source (an award, grant, contract, filing or funding round)
// reports it.
type ReceivedTransfer struct {
	// ID is the FundsTransfer's unique ID, such as "ted:<notice>".
	ID string
	// Reference is the source's own reference number for the transfer.
	Reference string
	Amount    float64
	// Currency defaults to USD.
	Currency string
	// Date is in any form support.TransferDate reads.
	Date string
	// Funder names the paying organization, related to the transfer as its
	// third_party; empty when the source names none.
	Funder string
}

// StoreReceivedTransfer writes t as a FundsTransfer received by the
// organization's default checking account (recipient), with the funder as
// its third_party, all tagged with src. A transfer without an ID or a
// positive amount, which the Asset Database rejects, is skipped without an
// error. It returns the transfer, or nil when nothing was stored.
func StoreReceivedTransfer(e *et.Event, orgent *dbt.Entity, t ReceivedTransfer, src *et.Source) *dbt.Entity {
	if t.ID == "" || t.Amount <= 0 {
		return nil
	}

	orgacc := OrgCheckingAccount(e.Session, orgent, src)
	if orgacc == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	currency := t.Currency
	if currency == "" {
		currency = "USD"
	}
	fundent, err := e.Session.DB().CreateAsset(ctx, &oamfin.FundsTransfer{
		ID:              t.ID,
		Amount:          t.Amount,
		Currency:        currency,
		ReferenceNumber: t.Reference,
		ExchangeDate:    support.TransferDate(t.Date),
	})
	if err != nil || fundent == nil {
		e.Session.Log().Error(fmt.Sprintf("failed to store the funds transfer %s: %v", t.ID, err),
			slog.Group("plugin", "name", src.Name))
		return nil
	}
	support.AddSource(ctx, e.Session, fundent, src)

	if _, err := support.Relate(ctx, e.Session, fundent,
		&oamgen.SimpleRelation{Name: "recipient"}, orgacc, src); err != nil {
		return nil
	}
	if funder := strings.TrimSpace(t.Funder); funder != "" {
		if fent, err := CreateOrgAsset(e.Session, nil, nil, &oamorg.Organization{Name: funder}, src); err == nil {
			_, _ = support.Relate(ctx, e.Session, fundent, &oamgen.SimpleRelation{Name: "third_party"}, fent, src)
		}
	}
	return fundent
}

// DispatchTransfers sends the funds transfers on as events.
func DispatchTransfers(e *et.Event, fundents ...*dbt.Entity) {
	for _, fundent := range fundents {
		f, ok := fundent.Asset.(*oamfin.FundsTransfer)
		if !ok {
			continue
		}
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fmt.Sprintf("%f:%s", f.Amount, f.ID),
			Entity:  fundent,
			Session: e.Session,
		})
	}
}

// OrgTransfersReceived returns the funds transfers src recorded since the
// time into the organization's default checking account, through account and
// recipient edges src vouches for, so a collector within its TTL can answer
// from the database.
func OrgTransfersReceived(sess et.Session, orgent *dbt.Entity, since time.Time, src *et.Source) []*dbt.Entity {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	var fundents []*dbt.Entity
	for _, acct := range checkingAccounts(ctx, sess, orgent, since, src) {
		edges, err := sess.DB().IncomingEdges(ctx, acct, since, "recipient")
		if err != nil {
			continue
		}
		for _, edge := range edges {
			if !support.Sourced(ctx, sess, edge, since, src) {
				continue
			}
			if a, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamfin.FundsTransfer); ok {
					fundents = append(fundents, a)
				}
			}
		}
	}
	return fundents
}

// checkingAccounts returns the organization's default checking accounts over
// account edges seen since the time, only those src vouches for when src is
// not nil.
func checkingAccounts(ctx context.Context, sess et.Session, orgent *dbt.Entity, since time.Time, src *et.Source) []*dbt.Entity {
	edges, err := sess.DB().OutgoingEdges(ctx, orgent, since, "account")
	if err != nil {
		return nil
	}

	var accts []*dbt.Entity
	for _, edge := range edges {
		if src != nil && !support.Sourced(ctx, sess, edge, since, src) {
			continue
		}
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
			if acc, ok := a.Asset.(*oamacct.Account); ok && acc.Type == oamacct.Checking && acc.Number == "default" {
				accts = append(accts, a)
			}
		}
	}
	return accts
}
