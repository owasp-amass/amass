// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
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

type fuzzyCompletions struct {
	name   string
	plugin *gleif
}

type relatedOrgs struct {
	name   string
	plugin *gleif
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
		Next  string `json:"next"`
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
				Name     string `json:"name"`
				Language string `json:"language"`
			} `json:"legalName"`
			OtherNames []struct {
				Name     string `json:"name"`
				Language string `json:"language"`
				Type     string `json:"type"`
			} `json:"otherNames"`
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
			EventGroups       []struct {
				GroupType string `json:"groupType"`
				Events    []struct {
					ValidationDocuments string `json:"validationDocuments"`
					EffectiveDate       string `json:"effectiveDate"`
					RecordedDate        string `json:"recordedDate"`
					Type                string `json:"type"`
					Status              string `json:"status"`
				} `json:"events"`
			} `json:"eventGroups"`
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
		BIC            []string `json:"bic"`
		MIC            []string `json:"mic"`
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
		FundManager struct {
			Links leiRelationshipLinks `json:"links"`
		} `json:"fund-manager"`
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
	Language                    string   `json:"language"`
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
