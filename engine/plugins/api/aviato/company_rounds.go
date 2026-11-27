// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aviato

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeop "github.com/owasp-amass/open-asset-model/people"
)

func (cr *companyRounds) check(e *et.Event) error {
	oamid, ok := e.Entity.Asset.(*oamgen.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	} else if oamid.Type != AviatoCompanyID {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(cr.plugin.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}
	if len(keys) == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Identifier), string(oam.Organization), cr.plugin.name)
	if err != nil {
		return err
	}

	if cr.plugin.identOrg(e, e.Entity) == nil {
		return nil
	}

	var fundents []*dbt.Entity
	src := &et.Source{
		Name:       cr.name,
		Confidence: cr.plugin.source.Confidence,
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		if orgent := cr.plugin.identOrg(e, e.Entity); orgent != nil {
			fundents = org.OrgTransfersReceived(e.Session, orgent, since, cr.plugin.source)
		}
	} else {
		fundents = cr.query(e, e.Entity, keys)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if len(fundents) > 0 {
		org.DispatchTransfers(e, fundents...)
	}
	return nil
}

func (cr *companyRounds) query(e *et.Event, ident *dbt.Entity, apikey []string) []*dbt.Entity {
	oamid := e.Entity.Asset.(*oamgen.Identifier)

	orgent := cr.plugin.identOrg(e, ident)
	if orgent == nil {
		msg := fmt.Sprintf("failed to find the Organization asset for %s", oamid.UniqueID)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		return []*dbt.Entity{}
	}

	page := 0
	total := 1
	perPage := 100
	var fundents []*dbt.Entity
loop:
	for _, key := range apikey {
		for ; page < total; page++ {
			headers := amasshttp.Header{"Content-Type": []string{"application/json"}}
			headers["Authorization"] = []string{"Bearer " + key}

			_ = support.WaitLimit(e.Session.Ctx(), cr.plugin.rlimit)
			e.Session.NetSem().Acquire()

			ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
			defer cancel()

			u := fmt.Sprintf("%s/company/%s/funding-rounds?perPage=%d&page=%d", cr.plugin.api,
				url.QueryEscape(oamid.ID), perPage, page)
			resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u, Header: headers})
			e.Session.NetSem().Release()
			if err != nil {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: %s", oamid.ID, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				// try the next key for the same page
				continue loop
			} else if resp.StatusCode != 200 {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: %s", oamid.ID, resp.Status)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue loop
			} else if resp.Body == "" {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: empty body", oamid.ID)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue loop
			} else if strings.Contains(resp.Body, `"error"`) {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: %s", oamid.ID, resp.Body)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue loop
			}

			var result companyRoundsResult
			if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
				msg := fmt.Sprintf("failed to unmarshal the funding rounds for %s: %s", oamid.ID, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				break loop
			} else if len(result.FundingRounds) == 0 {
				break loop
			}

			if len(result.FundingRounds) > 0 {
				if ents := cr.store(e, ident, orgent, &result); len(ents) > 0 {
					fundents = append(fundents, ents...)
				}
			}

			total = result.Pages
		}

		if page >= total {
			break
		}
	}
	return fundents
}

func (cr *companyRounds) store(e *et.Event, ident, orgent *dbt.Entity, funds *companyRoundsResult) []*dbt.Entity {
	var fundents []*dbt.Entity

	if orgent == nil {
		return fundents
	}
	o := orgent.Asset.(*oamorg.Organization)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	for _, round := range funds.FundingRounds {
		// A round without an announced amount is skipped (the Asset Database
		// rejects a FundsTransfer without a positive amount).
		if round.MoneyRaised <= 0 {
			continue
		}

		seedacc := cr.createSeedAccount(e, &round)
		if seedacc == nil {
			msg := fmt.Sprintf("failed to create the seed account for %s", o.Name)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		id := fmt.Sprintf("%s:%s", round.Name, round.Stage)
		fundent := org.StoreReceivedTransfer(e, orgent, org.ReceivedTransfer{
			ID: id, Amount: float64(round.MoneyRaised), Date: round.AnnouncedOn,
		}, cr.plugin.source)
		if fundent == nil {
			continue
		}

		if _, err := support.Relate(ctx, e.Session, fundent,
			oamgen.SimpleRelation{Name: "sender"}, seedacc, cr.plugin.source); err != nil {
			msg := fmt.Sprintf("failed to create the sender relation for %s: %s", id, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		fundents = append(fundents, fundent)
	}

	return fundents
}

func (cr *companyRounds) createSeedAccount(e *et.Event, round *companyFundingRound) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	name := fmt.Sprintf("%s:%s", round.Name, round.Stage)
	accountent, err := e.Session.DB().CreateAsset(ctx, &oamacct.Account{
		ID:      name,
		Type:    oamacct.Checking,
		Number:  "default",
		Balance: float64(round.MoneyRaised),
		Active:  false,
	})
	if err != nil {
		msg := fmt.Sprintf("failed to create the Account asset for %s: %s", name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		return nil
	}

	support.AddSource(ctx, e.Session, accountent, cr.plugin.source)

	investors := cr.createOrgInvestors(e, round)
	if ents := cr.createPersonInvestors(e, round); len(ents) > 0 {
		investors = append(investors, ents...)
	}

	for _, investor := range investors {
		if _, err := support.Relate(ctx, e.Session, investor,
			oamgen.SimpleRelation{Name: "account"}, accountent, cr.plugin.source); err != nil {
			msg := fmt.Sprintf("failed to create the account relation for %s: %s", investor.ID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		}
	}

	return accountent
}

func (cr *companyRounds) createOrgInvestors(e *et.Event, round *companyFundingRound) []*dbt.Entity {
	var investors []*dbt.Entity

	if len(round.CompanyInvestors) == 0 {
		return investors
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	for _, investor := range round.CompanyInvestors {
		oamid := &oamgen.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", AviatoCompanyID, investor.CompanyID),
			ID:       investor.CompanyID,
			Type:     AviatoCompanyID,
		}

		ident, err := e.Session.DB().CreateAsset(ctx, oamid)
		if err != nil || ident == nil {
			msg := fmt.Sprintf("failed to create the identifier asset for %s: %s", oamid.UniqueID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		var orgent *dbt.Entity
		// check if the Person asset already exists
		if edges, err := e.Session.DB().IncomingEdges(ctx, ident, time.Time{}, "id"); err == nil {
			for _, edge := range edges {
				if !support.Sourced(ctx, e.Session, edge, time.Time{}, cr.plugin.source) {
					continue
				}
				if a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*oamorg.Organization); ok {
						orgent = a
						break
					}
				}
			}
		}
		if orgent != nil {
			investors = append(investors, orgent)
			continue
		}

		// create the Organization asset
		o := &oamorg.Organization{Name: investor.Name}
		orgent, err = org.CreateOrgAsset(e.Session, nil, nil, o, cr.plugin.source)
		if err != nil {
			msg := fmt.Sprintf("failed to create the Organization asset for %s: %s", o.Name, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		if _, err := support.Relate(ctx, e.Session, orgent,
			oamgen.SimpleRelation{Name: "id"}, ident, cr.plugin.source); err != nil {
			msg := fmt.Sprintf("failed to create the id relation for %s: %s", oamid.UniqueID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    oamid.UniqueID,
			Entity:  ident,
			Session: e.Session,
		})
		investors = append(investors, orgent)
	}

	return investors
}

func (cr *companyRounds) createPersonInvestors(e *et.Event, round *companyFundingRound) []*dbt.Entity {
	var investors []*dbt.Entity

	if len(round.PersonInvestors) == 0 {
		return investors
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	for _, investor := range round.PersonInvestors {
		oamid := &oamgen.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", AviatoPersonID, investor.PersonID),
			ID:       investor.PersonID,
			Type:     AviatoPersonID,
		}

		ident, err := e.Session.DB().CreateAsset(ctx, oamid)
		if err != nil || ident == nil {
			msg := fmt.Sprintf("failed to create the identifier asset for %s: %s", oamid.UniqueID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		var personent *dbt.Entity
		// check if the Person asset already exists
		if edges, err := e.Session.DB().IncomingEdges(ctx, ident, time.Time{}, "id"); err == nil {
			for _, edge := range edges {
				if !support.Sourced(ctx, e.Session, edge, time.Time{}, cr.plugin.source) {
					continue
				}
				if a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*oampeop.Person); ok {
						personent = a
						break
					}
				}
			}
		}
		if personent != nil {
			investors = append(investors, personent)
			continue
		}

		// create the Person asset
		p := support.ListedPerson(investor.FullName)
		if p == nil {
			continue
		}

		personent, err = support.CreatePersonAsset(e.Session, nil, nil, p, cr.plugin.source)
		if err != nil {
			msg := fmt.Sprintf("failed to create the Person asset for %s: %s", p.FullName, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		if _, err := support.Relate(ctx, e.Session, personent,
			oamgen.SimpleRelation{Name: "id"}, ident, cr.plugin.source); err != nil {
			msg := fmt.Sprintf("failed to create the id relation for %s: %s", oamid.UniqueID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    oamid.UniqueID,
			Entity:  ident,
			Session: e.Session,
		})
		investors = append(investors, personent)
	}

	return investors
}
