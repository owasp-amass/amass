// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aviato

import (
	"log/slog"

	et "github.com/owasp-amass/amass/v4/engine/types"
	"golang.org/x/time/rate"
)

const (
	AviatoCompanyID = "aviato_company_id"
)

type aviato struct {
	name          string
	log           *slog.Logger
	rlimit        *rate.Limiter
	companySearch *companySearch
	employees     *employees
	source        *et.Source
}

type dsl struct {
	Offset  int                      `json:"offset"`
	Limit   int                      `json:"limit"`
	Filters []map[string]*dslEvalObj `json:"filters"`
}

type dslEvalObj struct {
	Operation string `json:"operation"`
	Value     string `json:"value"`
}

type companySearchResult struct {
	Count struct {
		Value      string `json:"value"`
		IsEstimate bool   `json:"isEstimate"`
	} `json:"count"`
	Items []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Country  string `json:"country"`
		Region   string `json:"region"`
		Locality string `json:"locality"`
		URLs     struct {
			Golden     string `json:"golden"`
			Contact    string `json:"contact"`
			Twitter    string `json:"twitter"`
			Website    string `json:"website"`
			Facebook   string `json:"facebook"`
			Linkedin   string `json:"linkedin"`
			Pitchbook  string `json:"pitchbook"`
			AngelList  string `json:"angelList"`
			SignalNFX  string `json:"signalNFX"`
			Crunchbase string `json:"crunchbase"`
		} `json:"URLs"`
		IndustryList []string `json:"industryList"`
	}
}

type companySearch struct {
	name   string
	plugin *aviato
}

type employees struct {
	name   string
	plugin *aviato
}

type employeesResult struct {
	Employees    []employeeResult `json:"employees"`
	Pages        int              `json:"pages"`
	TotalResults int              `json:"totalResults"`
}

type employeeResult struct {
	EntityType string `json:"entityType"`
	Person     struct {
		ID         string `json:"id"`
		FullName   string `json:"fullName"`
		EntityType string `json:"entityType"`
		Location   string `json:"location"`
		URLs       struct {
			Golden     string `json:"golden"`
			Contact    string `json:"contact"`
			Twitter    string `json:"twitter"`
			Website    string `json:"website"`
			Facebook   string `json:"facebook"`
			Linkedin   string `json:"linkedin"`
			Pitchbook  string `json:"pitchbook"`
			AngelList  string `json:"angelList"`
			SignalNFX  string `json:"signalNFX"`
			Crunchbase string `json:"crunchbase"`
		} `json:"URLs"`
		PersonID     string `json:"personID"`
		PositionList []struct {
			StartDate   string `json:"startDate"`
			EndDate     string `json:"endDate"`
			Title       string `json:"title"`
			Description string `json:"description"`
		} `json:"positionList"`
		CompanyID   string `json:"companyID"`
		CompanyName string `json:"companyName"`
		StartDate   string `json:"startDate"`
		EndDate     string `json:"endDate"`
		LinkedinID  string `json:"linkedinID"`
	} `json:"person"`
}
