// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/account"
	"github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
)

func (cr *companyRounds) check(e *et.Event) error {
	oamid, ok := e.Entity.Asset.(*general.Identifier)
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

	var fundents []*dbt.Entity
	src := &et.Source{
		Name:       cr.name,
		Confidence: cr.plugin.source.Confidence,
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		fundents = cr.lookup(e, e.Entity, since)
	} else {
		fundents = cr.query(e, e.Entity, keys)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if len(fundents) > 0 {
		cr.process(e, fundents)
	}
	return nil
}

func (cr *companyRounds) lookup(e *et.Event, ident *dbt.Entity, since time.Time) []*dbt.Entity {
	var orgent *dbt.Entity

	if edges, err := e.Session.Cache().IncomingEdges(ident, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, cr.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					orgent = a
					break
				}
			}
		}
	}

	var fundents []*dbt.Entity
	if orgent == nil {
		return fundents
	}

	var accountents []*dbt.Entity
	if edges, err := e.Session.Cache().OutgoingEdges(orgent, since, "account"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, cr.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if acc, ok := a.Asset.(*account.Account); ok && acc.Type == account.Checking && acc.Number == "default" {
					accountents = append(accountents, a)
				}
			}
		}
	}

	for _, ent := range accountents {
		if edges, err := e.Session.Cache().IncomingEdges(ent, since, "recipient"); err == nil {
			for _, edge := range edges {
				if tags, err := e.Session.Cache().GetEdgeTags(edge, since, cr.plugin.source.Name); err != nil || len(tags) == 0 {
					continue
				}
				if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*financial.FundsTransfer); ok {
						fundents = append(fundents, a)
					}
				}
			}
		}
	}

	return fundents
}

func (cr *companyRounds) query(e *et.Event, ident *dbt.Entity, apikey []string) []*dbt.Entity {
	oamid := e.Entity.Asset.(*general.Identifier)

	orgent := cr.getAssociatedOrg(e, ident)
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
			headers := http.Header{"Content-Type": []string{"application/json"}}
			headers["Authorization"] = []string{"Bearer " + key}

			_ = cr.plugin.rlimit.Wait(context.TODO())
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			u := fmt.Sprintf("https://data.api.aviato.co/company/%s/funding-rounds?perPage=%d&page=%d", url.QueryEscape(oamid.ID), perPage, page)
			resp, err := http.RequestWebPage(ctx, &http.Request{URL: u, Header: headers})
			if err != nil {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: %s", oamid.ID, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue
			} else if resp.StatusCode != 200 {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: %s", oamid.ID, resp.Status)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue
			} else if resp.Body == "" {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: empty body", oamid.ID)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue
			} else if strings.Contains(resp.Body, "error") {
				msg := fmt.Sprintf("failed to obtain the funding rounds for %s: %s", oamid.ID, resp.Body)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
				continue
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

func (cr *companyRounds) getAssociatedOrg(e *et.Event, ident *dbt.Entity) *dbt.Entity {
	var orgent *dbt.Entity

	if edges, err := e.Session.Cache().IncomingEdges(ident, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					orgent = a
					break
				}
			}
		}
	}

	return orgent
}

func (cr *companyRounds) store(e *et.Event, ident, orgent *dbt.Entity, funds *companyRoundsResult) []*dbt.Entity {
	var fundents []*dbt.Entity

	if orgent == nil {
		return fundents
	}
	o := orgent.Asset.(*org.Organization)

	for _, round := range funds.FundingRounds {
		orgacc := cr.orgCheckingAccount(e, orgent)
		if orgacc == nil {
			msg := fmt.Sprintf("failed to create the checking account for %s", o.Name)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		seedacc := cr.createSeedAccount(e, &round)
		if seedacc == nil {
			msg := fmt.Sprintf("failed to create the seed account for %s", o.Name)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		f := &financial.FundsTransfer{
			ID:           fmt.Sprintf("%s:%s", round.Name, round.Stage),
			Amount:       float64(round.MoneyRaised),
			Currency:     "USD",
			ExchangeDate: round.AnnouncedOn,
		}

		fundent, err := e.Session.Cache().CreateAsset(f)
		if err != nil {
			msg := fmt.Sprintf("failed to create the FundsTransfer asset for %s: %s", f.ID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		_, err = e.Session.Cache().CreateEntityProperty(fundent, &general.SourceProperty{
			Source:     cr.plugin.source.Name,
			Confidence: cr.plugin.source.Confidence,
		})
		if err != nil {
			msg := fmt.Sprintf("failed to create the FundsTransfer asset source property for %s: %s", f.ID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		if err := cr.plugin.createRelation(e.Session, fundent,
			general.SimpleRelation{Name: "recipient"}, orgacc, cr.plugin.source.Confidence); err != nil {
			msg := fmt.Sprintf("failed to create the recipient relation for %s: %s", f.ID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		if err := cr.plugin.createRelation(e.Session, fundent,
			general.SimpleRelation{Name: "sender"}, seedacc, cr.plugin.source.Confidence); err != nil {
			msg := fmt.Sprintf("failed to create the sender relation for %s: %s", f.ID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		fundents = append(fundents, fundent)
	}

	return fundents
}

func (cr *companyRounds) orgCheckingAccount(e *et.Event, orgent *dbt.Entity) *dbt.Entity {
	var accountent *dbt.Entity
	o := orgent.Asset.(*org.Organization)

	if edges, err := e.Session.Cache().OutgoingEdges(orgent, time.Time{}, "account"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if acc, ok := a.Asset.(*account.Account); ok && acc.Type == account.Checking && acc.Number == "default" {
					accountent = a
					break
				}
			}
		}
	}

	if accountent == nil {
		ent, err := e.Session.Cache().CreateAsset(&account.Account{
			ID:      uuid.New().String(),
			Type:    account.Checking,
			Number:  "default",
			Balance: 0,
			Active:  o.Active,
		})
		if err != nil {
			msg := fmt.Sprintf("failed to create the Account asset for %s: %s", o.Name, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			return nil
		}

		accountent = ent
	}

	_, err := e.Session.Cache().CreateEntityProperty(accountent, &general.SourceProperty{
		Source:     cr.plugin.source.Name,
		Confidence: cr.plugin.source.Confidence,
	})
	if err != nil {
		msg := fmt.Sprintf("failed to create the Account asset source property for %s: %s", o.Name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		return nil
	}

	if err := cr.plugin.createRelation(e.Session, orgent,
		general.SimpleRelation{Name: "account"}, accountent, cr.plugin.source.Confidence); err != nil {
		msg := fmt.Sprintf("failed to create the account relation for %s: %s", o.Name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
	}

	return accountent
}

func (cr *companyRounds) createSeedAccount(e *et.Event, round *companyFundingRound) *dbt.Entity {
	name := fmt.Sprintf("%s:%s", round.Name, round.Stage)
	accountent, err := e.Session.Cache().CreateAsset(&account.Account{
		ID:      name,
		Type:    account.Checking,
		Number:  "default",
		Balance: float64(round.MoneyRaised),
		Active:  false,
	})
	if err != nil {
		msg := fmt.Sprintf("failed to create the Account asset for %s: %s", name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		return nil
	}

	_, err = e.Session.Cache().CreateEntityProperty(accountent, &general.SourceProperty{
		Source:     cr.plugin.source.Name,
		Confidence: cr.plugin.source.Confidence,
	})
	if err != nil {
		msg := fmt.Sprintf("failed to create the Account asset source property for %s: %s", name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
		return nil
	}

	investors := cr.createOrgInvestors(e, round)
	if ents := cr.createPersonInvestors(e, round); len(ents) > 0 {
		investors = append(investors, ents...)
	}

	for _, investor := range investors {
		if err := cr.plugin.createRelation(e.Session, investor,
			general.SimpleRelation{Name: "account"}, accountent, cr.plugin.source.Confidence); err != nil {
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

	for _, investor := range round.CompanyInvestors {
		oamid := &general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", AviatoCompanyID, investor.CompanyID),
			ID:       investor.CompanyID,
			Type:     AviatoCompanyID,
		}

		ident, err := e.Session.Cache().CreateAsset(oamid)
		if err != nil || ident == nil {
			msg := fmt.Sprintf("failed to create the identifier asset for %s: %s", oamid.UniqueID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		var orgent *dbt.Entity
		// check if the Person asset already exists
		if edges, err := e.Session.Cache().IncomingEdges(ident, time.Time{}, "id"); err == nil {
			for _, edge := range edges {
				if tags, err := e.Session.Cache().GetEdgeTags(edge, time.Time{}, cr.plugin.source.Name); err != nil || len(tags) == 0 {
					continue
				}
				if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*org.Organization); ok {
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
		o := &org.Organization{Name: investor.Name}
		orgent, err = support.CreateOrgAsset(e.Session, nil, nil, o, cr.plugin.source)
		if err != nil {
			msg := fmt.Sprintf("failed to create the Organization asset for %s: %s", o.Name, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		_, err = e.Session.Cache().CreateEntityProperty(orgent, &general.SourceProperty{
			Source:     cr.plugin.source.Name,
			Confidence: cr.plugin.source.Confidence,
		})
		if err != nil {
			msg := fmt.Sprintf("failed to create the Organization asset source property for %s: %s", o.Name, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		if err := cr.plugin.createRelation(e.Session, orgent,
			general.SimpleRelation{Name: "id"}, ident, cr.plugin.source.Confidence); err != nil {
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

	for _, investor := range round.PersonInvestors {
		oamid := &general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", AviatoPersonID, investor.PersonID),
			ID:       investor.PersonID,
			Type:     AviatoPersonID,
		}

		ident, err := e.Session.Cache().CreateAsset(oamid)
		if err != nil || ident == nil {
			msg := fmt.Sprintf("failed to create the identifier asset for %s: %s", oamid.UniqueID, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		var personent *dbt.Entity
		// check if the Person asset already exists
		if edges, err := e.Session.Cache().IncomingEdges(ident, time.Time{}, "id"); err == nil {
			for _, edge := range edges {
				if tags, err := e.Session.Cache().GetEdgeTags(edge, time.Time{}, cr.plugin.source.Name); err != nil || len(tags) == 0 {
					continue
				}
				if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*people.Person); ok {
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
		p := support.FullNameToPerson(investor.FullName)
		if p == nil {
			continue
		}

		personent, err = e.Session.Cache().CreateAsset(p)
		if err != nil {
			msg := fmt.Sprintf("failed to create the Person asset for %s: %s", p.FullName, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		_, err = e.Session.Cache().CreateEntityProperty(personent, &general.SourceProperty{
			Source:     cr.plugin.source.Name,
			Confidence: cr.plugin.source.Confidence,
		})
		if err != nil {
			msg := fmt.Sprintf("failed to create the Person asset source property for %s: %s", p.FullName, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", cr.plugin.name, "handler", cr.name))
			continue
		}

		if err := cr.plugin.createRelation(e.Session, personent,
			general.SimpleRelation{Name: "id"}, ident, cr.plugin.source.Confidence); err != nil {
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

func (cr *companyRounds) process(e *et.Event, fundents []*dbt.Entity) {
	for _, fund := range fundents {
		f := fund.Asset.(*financial.FundsTransfer)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fmt.Sprintf("%f:%s", f.Amount, f.ID),
			Entity:  fund,
			Session: e.Session,
		})
	}
}
