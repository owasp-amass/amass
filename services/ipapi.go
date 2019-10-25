// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// IPAPI is the Service that handles access to the ipapi data source.
type IPAPI struct {
	BaseService

	SourceType string
}

// NewIPAPI returns he object initialized, but not yet started.
func NewIPAPI(sys System) *IPAPI {
	i := &IPAPI{SourceType: requests.API}

	i.BaseService = *NewBaseService(i, "ipapi", sys)
	return i
}

// Type implements the Service interface.
func (i *IPAPI) Type() string {
	return i.SourceType
}

// OnStart implements the Service interface.
func (i *IPAPI) OnStart() error {
	i.BaseService.OnStart()

	i.SetRateLimit(time.Second)
	return nil
}

// OnAddrRequest implements the Service interface.
func (i *IPAPI) OnAddrRequest(ctx context.Context, req *requests.AddrRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	if req == nil || req.Address == "" {
		return
	}

	i.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, i.String())

	url := i.restAddrURL(req.Address)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", i.String(), url, err))
		return
	}
	// Extract the IP address information from the REST API results
	var info struct {
		City        string  `json:"city"`
		Region      string  `json:"region"`
		RegionCode  string  `json:"region_code"`
		Country     string  `json:"country"`
		CountryName string  `json:"country_name"`
		PostalCode  string  `json:"postal"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Timezone    string  `json:"timezone"`
		ASN         string  `json:"asn"`
		Description string  `json:"org"`
	}
	if err := json.Unmarshal([]byte(page), &info); err != nil {
		return
	}
}

func (i *IPAPI) restAddrURL(addr string) string {
	return fmt.Sprintf("https://ipapi.co/%s/json", addr)
}
