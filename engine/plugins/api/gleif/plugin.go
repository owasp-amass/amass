// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
	"go.uber.org/ratelimit"
)

type gleif struct {
	name    string
	log     *slog.Logger
	rlimit  ratelimit.Limiter
	fuzzy   *fuzzyCompletions
	related *relatedOrgs
	source  *et.Source
}

func NewGLEIF() et.Plugin {
	return &gleif{
		name:   "GLEIF",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
		source: &et.Source{
			Name:       "GLEIF",
			Confidence: 100,
		},
	}
}

func (g *gleif) Name() string {
	return g.name
}

func (g *gleif) Start(r et.Registry) error {
	g.log = r.Log().WithGroup("plugin").With("name", g.name)

	g.fuzzy = &fuzzyCompletions{
		name:   g.name + "-Fuzzy-Handler",
		plugin: g,
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       g,
		Name:         g.fuzzy.name,
		Priority:     6,
		MaxInstances: 1,
		Transforms:   []string{string(oam.Identifier)},
		EventType:    oam.Organization,
		Callback:     g.fuzzy.check,
	}); err != nil {
		return err
	}

	g.related = &relatedOrgs{
		name:   g.name + "-LEI-Handler",
		plugin: g,
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       g,
		Name:         g.related.name,
		Priority:     6,
		MaxInstances: 1,
		Transforms:   []string{string(oam.Organization)},
		EventType:    oam.Identifier,
		Callback:     g.related.check,
	}); err != nil {
		return err
	}

	g.log.Info("Plugin started")
	return nil
}

func (g *gleif) Stop() {
	g.log.Info("Plugin stopped")
}

type singleResponse struct {
	Meta struct {
		GoldenCopy struct {
			PublishDate string `json:"publishDate"`
		} `json:"goldenCopy"`
	} `json:"meta"`
	Data leiRecord `json:"data"`
}

type multipleResponse struct {
	Meta struct {
		GoldenCopy struct {
			PublishDate string `json:"publishDate"`
		} `json:"goldenCopy"`
		Pagination struct {
			CurrentPage int `json:"currentPage"`
			PerPage     int `json:"perPage"`
			From        int `json:"from"`
			To          int `json:"to"`
			Total       int `json:"total"`
			LastPage    int `json:"lastPage"`
		} `json:"pagination"`
	} `json:"meta"`
	Links struct {
		First string `json:"first"`
		Last  string `json:"last"`
	} `json:"links"`
	Data []leiRecord `json:"data"`
}

type leiRecord struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		LEI    string `json:"lei"`
		Entity struct {
			LegalName struct {
				Name string `json:"name"`
				Lang string `json:"language"`
			} `json:"legalName"`
			OtherNames               []string   `json:"otherNames"`
			TransliteratedOtherNames []string   `json:"transliteratedOtherNames"`
			LegalAddress             leiAddress `json:"legalAddress"`
			HeadquartersAddress      leiAddress `json:"headquartersAddress"`
			RegisteredAt             struct {
				ID    string `json:"id"`
				Other string `json:"other"`
			} `json:"registeredAt"`
			RegisteredAs string `json:"registeredAs"`
			Jurisdiction string `json:"jurisdiction"`
			Category     string `json:"category"`
			LegalForm    struct {
				ID    string `json:"id"`
				Other string `json:"other"`
			} `json:"legalForm"`
			AssociatedEntity leiEntity `json:"associatedEntity"`
			Status           string    `json:"status"`
			Expiration       struct {
				Date   string `json:"date"`
				Reason string `json:"reason"`
			} `json:"expiration"`
			SuccessorEntity   leiEntity    `json:"successorEntity"`
			SuccessorEntities []leiEntity  `json:"successorEntities"`
			CreationDate      string       `json:"creationDate"`
			SubCategory       string       `json:"subCategory"`
			OtherAddresses    []leiAddress `json:"otherAddresses"`
			EventGroups       []string     `json:"eventGroups"`
		} `json:"entity"`
		Registration struct {
			InitialRegistrationDate string `json:"initialRegistrationDate"`
			LastUpdateDate          string `json:"lastUpdateDate"`
			Status                  string `json:"status"`
			NextRenewalDate         string `json:"nextRenewalDate"`
			ManagingLOU             string `json:"managingLou"`
			CorroborationLevel      string `json:"corroborationLevel"`
			ValidatedAt             struct {
				ID    string `json:"id"`
				Other string `json:"other"`
			} `json:"validatedAt"`
			ValidatedAs                string   `json:"validatedAs"`
			OtherValidationAuthorities []string `json:"otherValidationAuthorities"`
		} `json:"registration"`
		BIC            string   `json:"bic"`
		MIC            string   `json:"mic"`
		OCID           string   `json:"ocid"`
		SPGlobal       []string `json:"spglobal"`
		ConformityFlag string   `json:"conformityFlag"`
	} `json:"attributes"`
	Relationships struct {
		ManagingLOU struct {
			Links leiRelationshipLinks `json:"links"`
		} `json:"managing-lou"`
		LEIIssuer struct {
			Links leiRelationshipLinks `json:"links"`
		} `json:"lei-issuer"`
		FieldModifications struct {
			Links leiRelationshipLinks `json:"links"`
		} `json:"field-modifications"`
		DirectParent struct {
			Links leiRelationshipLinks `json:"links"`
		} `json:"direct-parent"`
		UltimateParent struct {
			Links leiRelationshipLinks `json:"links"`
		} `json:"ultimate-parent"`
		DirectChildren struct {
			Links leiRelationshipLinks `json:"links"`
		} `json:"direct-children"`
		UltimateChildren struct {
			Links leiRelationshipLinks `json:"links"`
		} `json:"ultimate-children"`
		ISINs struct {
			Links leiRelationshipLinks `json:"links"`
		} `json:"isins"`
	} `json:"relationships"`
	Links struct {
		Self string `json:"self"`
	} `json:"links"`
}

type leiEntity struct {
	LEI  string `json:"lei"`
	Name string `json:"name"`
}

type leiAddress struct {
	Lang                        string   `json:"language"`
	AddressLines                []string `json:"addressLines"`
	AddressNumber               string   `json:"addressNumber"`
	AddressNumberWithinBuilding string   `json:"addressNumberWithinBuilding"`
	MailRouting                 string   `json:"mailRouting"`
	City                        string   `json:"city"`
	Region                      string   `json:"region"`
	Country                     string   `json:"country"`
	PostalCode                  string   `json:"postalCode"`
}

type leiRelationshipLinks struct {
	Related             string `json:"related"`
	LEIRecord           string `json:"lei-record"`
	RelationshipRecord  string `json:"relationship-record"`
	RelationshipRecords string `json:"relationship-records"`
	ReportingException  string `json:"reporting-exception"`
}

func (g *gleif) getLEIRecord(e *et.Event, ident *general.Identifier) (*leiRecord, error) {
	g.rlimit.Take()

	u := "https://api.gleif.org/api/v1/lei-records/" + ident.EntityID
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
	if err != nil || resp.Body == "" {
		return nil, err
	}

	var result singleResponse
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return nil, err
	} else if len(result.Data.ID) == 0 {
		return nil, errors.New("failed to find LEI record")
	}
	return &result.Data, nil
}

func (g *gleif) orgEntityToLEI(e *et.Event, orgent *dbt.Entity) *dbt.Entity {
	if edges, err := e.Session.Cache().OutgoingEdges(orgent, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if id, ok := a.Asset.(*general.Identifier); ok && id.Type == general.LEICode {
					return a
				}
			}
		}
	}
	return nil
}

func (g *gleif) leiToOrgEntity(e *et.Event, ident *dbt.Entity) *dbt.Entity {
	if edges, err := e.Session.Cache().IncomingEdges(ident, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					return a
				}
			}
		}
	}
	return nil
}

func (g *gleif) updateOrgFromLEIRecord(e *et.Event, orgent *dbt.Entity, lei *leiRecord) {
	o := orgent.Asset.(*org.Organization)

	o.LegalName = lei.Attributes.Entity.LegalName.Name
	o.FoundingDate = lei.Attributes.Entity.CreationDate
	if lei.Attributes.Entity.Status == "ACTIVE" {
		o.Active = true
	} else {
		o.Active = false
	}

	street := strings.Join(lei.Attributes.Entity.HeadquartersAddress.AddressLines, " ")
	city := lei.Attributes.Entity.HeadquartersAddress.City
	province := lei.Attributes.Entity.HeadquartersAddress.Region
	postalCode := lei.Attributes.Entity.HeadquartersAddress.PostalCode
	country := lei.Attributes.Entity.HeadquartersAddress.Country

	addr := fmt.Sprintf("%s %s %s %s %s", street, city, province, postalCode, country)
	_ = g.addAddress(e, orgent, general.SimpleRelation{Name: "location"}, addr)
}

func (g *gleif) addAddress(e *et.Event, orgent *dbt.Entity, rel oam.Relation, addr string) error {
	loc := support.StreetAddressToLocation(addr)
	if loc == nil {
		return errors.New("failed to create location")
	}

	a, err := e.Session.Cache().CreateAsset(loc)
	if err != nil || a == nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", g.name, "handler", g.name))
		return err
	}

	_, _ = e.Session.Cache().CreateEntityProperty(a, &general.SourceProperty{
		Source:     g.source.Name,
		Confidence: g.source.Confidence,
	})

	edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   rel,
		FromEntity: orgent,
		ToEntity:   a,
	})
	if err != nil && edge == nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", g.name, "handler", g.name))
		return err
	}

	_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
		Source:     g.source.Name,
		Confidence: g.source.Confidence,
	})

	return nil
}
