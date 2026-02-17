// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	biter "github.com/biter777/countries"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/open-asset-model/contact"
	pioz "github.com/pioz/countries"
)

type parsedComponent struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type parsed struct {
	Parts []parsedComponent `json:"parts"`
}

type parseRequest struct {
	Address  string `json:"addr"`
	Language string `json:"lang"`
	Country  string `json:"country"`
}

var postalReqAvail chan struct{}
var postalResponseAvail chan bool
var postalHost, postalPort string

func init() {
	postalHost = os.Getenv("POSTAL_SERVER_HOST")
	if postalHost == "" {
		postalHost = "0.0.0.0"
	}

	postalPort = os.Getenv("POSTAL_SERVER_PORT")
	if postalPort == "" {
		postalPort = "4001"
	}

	postalReqAvail = make(chan struct{}, 1)
	postalResponseAvail = make(chan bool, 1)
	go postalServerHeartbeat()
}

func CountryToAlpha2Code(country string) string {
	if code := biter.ByName(country); code.IsValid() {
		return code.Alpha2()
	}
	return country
}

func StreetAddressToLocation(address string) *contact.Location {
	if address == "" {
		return nil
	}

	parts, err := postalServerParseAddress(address)
	if err != nil {
		return nil
	}

	loc := &contact.Location{Address: address}
	for _, part := range parts {
		switch part.Label {
		case "house":
			loc.Building = part.Value
		case "house_number":
			loc.BuildingNumber = part.Value
		case "road":
			loc.StreetName = part.Value
		case "unit":
			loc.Unit = part.Value
		case "po_box":
			loc.POBox = part.Value
		case "city":
			loc.City = part.Value
		case "state":
			loc.Province = part.Value
		case "postcode":
			loc.PostalCode = part.Value
		case "country":
			loc.Country = CountryToAlpha2Code(part.Value)
		case "suburb":
			fallthrough
		case "city_district":
			if s := part.Value; s != "" {
				loc.Locality = s
			}
		}
	}

	// attempt to convert the province to its two-letter abbreviation
	if loc.Country != "" && len(loc.Province) > 2 {
		if c := pioz.Get(loc.Country); c != nil {
			if sub := c.SubdivisionByName(loc.Province); sub.Type != "" {
				loc.Province = sub.Code
			}
		}
	}

	return loc
}

func postalServerParseAddress(address string) ([]parsedComponent, error) {
	if !isPostalServerAvailable() {
		return nil, errors.New("libpostal is not available")
	}

	reqJSON, err := json.Marshal(parseRequest{Address: address})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, &amasshttp.Request{
		Method: "POST",
		URL:    "http://" + postalHost + ":" + postalPort + "/parse",
		Body:   string(reqJSON),
	})
	if err != nil {
		return nil, err
	}

	var p parsed
	if err := json.Unmarshal([]byte("{\"parts\":"+resp.Body+"}"), &p); err != nil {
		return nil, err
	}
	return p.Parts, nil
}

func checkPostalServerHealth() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if resp, err := amasshttp.RequestWebPage(ctx, &amasshttp.Request{
		URL: "http://" + postalHost + ":" + postalPort + "/health",
	}); err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return false
	}
	return true
}

func isPostalServerAvailable() bool {
	postalReqAvail <- struct{}{}
	return <-postalResponseAvail
}

func postalServerHeartbeat() {
	avail := checkPostalServerHealth()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			avail = checkPostalServerHealth()
		case <-postalReqAvail:
			postalResponseAvail <- avail
		}
	}
}
