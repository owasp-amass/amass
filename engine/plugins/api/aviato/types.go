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
	AviatoPersonID  = "aviato_person_id"
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
		ID           string    `json:"id"`
		Name         string    `json:"name"`
		Country      string    `json:"country"`
		Region       string    `json:"region"`
		Locality     string    `json:"locality"`
		URLs         URLResult `json:"URLs"`
		IndustryList []string  `json:"industryList"`
	} `json:"items"`
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
	StartDate    string `json:"startDate"`
	EndDate      string `json:"endDate"`
	EntityType   string `json:"entityType"`
	PositionList []struct {
		StartDate   string `json:"startDate"`
		EndDate     string `json:"endDate"`
		Title       string `json:"title"`
		Description string `json:"description"`
	} `json:"positionList"`
	PersonID    string `json:"personID"`
	CompanyID   string `json:"companyID"`
	CompanyName string `json:"companyName"`
	Person      struct {
		ID         string    `json:"id"`
		FullName   string    `json:"fullName"`
		EntityType string    `json:"entityType"`
		Location   string    `json:"location"`
		URLs       URLResult `json:"URLs"`
	} `json:"person"`
}

type companyEnrichResult struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	LegalName       string   `json:"legalName"`
	AlternateNames  []string `json:"alternateNames"`
	CageCode        string   `json:"cageCode"`
	CIKNumber       string   `json:"CIKNumber"`
	DunsNumber      string   `json:"dunsNumber"`
	LinkedinID      string   `json:"linkedinID"`
	NAICSCode       string   `json:"NAICSCode"`
	StockSymbol     string   `json:"stockSymbol"`
	Status          string   `json:"status"`
	Tagline         string   `json:"tagline"`
	Founded         string   `json:"founded"`
	OwnershipStatus string   `json:"ownershipStatus"`
	Headcount       int      `json:"headcount"`
	Description     string   `json:"description"`
	IsAcquired      bool     `json:"isAcquired"`
	IsExited        bool     `json:"isExited"`
	IsGovernment    bool     `json:"isGovernment"`
	IsNonProfit     bool     `json:"isNonProfit"`
	IsShutDown      bool     `json:"isShutDown"`
	Locality        string   `json:"locality"`
	Region          string   `json:"region"`
	Country         string   `json:"country"`
	LocationDetails struct {
		Continent     LocationDetails `json:"continent"`
		Country       LocationDetails `json:"country"`
		County        LocationDetails `json:"county"`
		LocalAdmin    LocationDetails `json:"localadmin"`
		Locality      LocationDetails `json:"locality"`
		Borough       LocationDetails `json:"borough"`
		Macroregion   LocationDetails `json:"macroregion"`
		Region        LocationDetails `json:"region"`
		Macrohood     LocationDetails `json:"macrohood"`
		Neighbourhood LocationDetails `json:"neighbourhood"`
	} `json:"locationDetails"`
	LocationIDList    []int    `json:"locationIDList"`
	IndustryList      []string `json:"industryList"`
	BusinessModelList []string `json:"businessModelList"`
	ProductList       []struct {
		ProductName    string `json:"productName"`
		Tagline        string `json:"tagline"`
		CreatedAt      string `json:"createdAt"`
		ImageID        string `json:"imageID"`
		ProductURL     string `json:"productURL"`
		ProductHuntURL string `json:"producthuntURL"`
	} `json:"productList"`
	CustomerTypes  []string `json:"customerTypes"`
	JobFamilyList  []string `json:"jobFamilyList"`
	JobListingList []struct {
		Category    string   `json:"category"`
		SubCategory string   `json:"subCategory"`
		Title       string   `json:"title"`
		IsFullTime  bool     `json:"isFullTime"`
		IsRemote    bool     `json:"isRemote"`
		Locations   []string `json:"locations"`
		Description string   `json:"mdDescription"`
		Slug        string   `json:"slug"`
		URL         string   `json:"url"`
	} `json:"jobListingList"`
	ScreenshotList   []string `json:"screenshotList"`
	TargetMarketList []string `json:"targetMarketList"`
	TechStackList    []struct {
		ProductName       string   `json:"productName"`
		ProductCategories []string `json:"productCategories"`
	} `json:"techStackList"`
	URLs              URLResult `json:"URLs"`
	LinkedinFollowers int       `json:"linkedinFollowers"`
	WebTrafficSources struct {
		Mail          float64 `json:"mail"`
		Direct        float64 `json:"direct"`
		Search        float64 `json:"search"`
		Social        float64 `json:"social"`
		Referrals     float64 `json:"referrals"`
		PaidReferrals float64 `json:"paidReferrals"`
	} `json:"webTrafficSources"`
	AcquiredBy struct {
		ID           int     `json:"id"`
		AnnouncedOn  string  `json:"announcedOn"`
		AcquirerName string  `json:"acquirerName"`
		AcquireeName string  `json:"acquireeName"`
		Price        float64 `json:"price"`
	} `json:"acquiredBy"`
	EmbeddedNews []struct {
		Date     string `json:"date"`
		Title    string `json:"title"`
		Author   string `json:"author"`
		Source   string `json:"source"`
		URL      string `json:"linkUrl"`
		ImageURL string `json:"imageUrl"`
	} `json:"embeddedNews"`
	PatentCount  int `json:"patentCount"`
	OwnedPatents []struct {
		InventionTitle   string `json:"inventionTitle"`
		DatePublished    string `json:"datePublished"`
		DocumentID       string `json:"documentId"`
		DocumentURL      string `json:"documentUrl"`
		LatestFilingDate string `json:"latestFilingDate"`
	} `json:"ownedPatents"`
	GovernmentAwards struct {
		AwardID       string  `json:"awardId"`
		AwardType     string  `json:"awardType"`
		AwardAmount   float64 `json:"awardAmount"`
		StartDate     string  `json:"startDate"`
		EndDate       string  `json:"endDate"`
		ActionDate    string  `json:"actionDate"`
		DateSigned    string  `json:"dateSigned"`
		TopTierAgency string  `json:"awardingTopTierAgency"`
		SubTierAgency string  `json:"awardingSubTierAgency"`
		Description   string  `json:"productOrServiceDescription"`
		CFDAProgram   string  `json:"cfdaProgram"`
	} `json:"governmentAwards"`
	FinancingStatus    string  `json:"financingStatus"`
	TotalFunding       float64 `json:"totalFunding"`
	InvestorCount      int     `json:"investorCount"`
	FundingRoundCount  int     `json:"fundingRoundCount"`
	LastRoundValuation float64 `json:"lastRoundValuation"`
	LatestDealDate     string  `json:"latestDealDate"`
	LatestDealType     string  `json:"latestDealType"`
	LatestDealAmount   int     `json:"latestDealAmount"`
	StockExchange      string  `json:"stockExchange"`
	IPODate            string  `json:"ipoDate"`
	SharePrice         float64 `json:"sharePrice"`
	OutstandingShares  float64 `json:"outstandingShares"`
	MarketCap          float64 `json:"marketCap"`
}

type URLResult struct {
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
}

type LocationDetails struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	PlaceType string `json:"placeType"`
	Geometry  struct {
		AreaSquareDegrees float64 `json:"area_square_degrees"`
		BoundingBox       string  `json:"bbox"`
		Latitude          float64 `json:"lat"`
		Longitude         float64 `json:"lon"`
	} `json:"geometry"`
}
