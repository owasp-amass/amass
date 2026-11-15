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
	"strings"
	"time"

	biter "github.com/biter777/countries"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/open-asset-model/contact"
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

// StreetAddressToLocation parses an address with libpostal and returns the
// Location it names, or nil when the address cannot be parsed. The same
// place written different ways becomes the same Location: its Address is
// built from the parsed parts in standard form (see address_forms.json).
func StreetAddressToLocation(address string) *contact.Location {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil
	}

	parts, err := postalServerParseAddress(address)
	if err != nil {
		return nil
	}

	return locationFromParts(address, parts)
}

// locationFromParts builds a Location from the parts libpostal found in an
// address. The parts are put in standard form, and the Address is the
// standard one-line form of the number, street, unit, PO box, city,
// province, postal code and country; a building name is part of it only
// when there is no street. Without any of those parts, the Address is the
// one given.
func locationFromParts(address string, parts []parsedComponent) *contact.Location {
	loc := &contact.Location{}
	for _, part := range parts {
		v := strings.TrimSpace(part.Value)
		switch part.Label {
		case "house":
			loc.Building = v
		case "house_number":
			loc.BuildingNumber = v
		case "road":
			loc.StreetName = v
		case "unit":
			loc.Unit = v
		case "po_box":
			loc.POBox = v
		case "city":
			loc.City = v
		case "state":
			loc.Province = v
		case "postcode":
			loc.PostalCode = v
		case "country":
			loc.Country = CountryToAlpha2Code(v)
		case "suburb", "city_district":
			if v != "" {
				loc.Locality = v
			}
		}
	}

	// the province's code, from its name in any language the country data has
	if loc.Country != "" && len(loc.Province) > 2 {
		loc.Province = provinceCode(loc.Province, loc.Country)
	}

	country := strings.ToUpper(loc.Country)
	loc.Country = country
	loc.BuildingNumber = cleanAddressPart(loc.BuildingNumber)
	loc.StreetName = standardStreet(loc.StreetName, country)
	loc.Unit = standardUnit(loc.Unit, country)
	loc.POBox = standardPOBox(loc.POBox, country)
	loc.City = cleanAddressPart(loc.City)
	loc.Locality = cleanAddressPart(loc.Locality)
	loc.Province = strings.ToUpper(cleanAddressPart(loc.Province))
	loc.PostalCode = standardPostcode(loc.PostalCode, country)

	loc.Address = standardAddress(loc)
	if loc.Address == "" {
		loc.Address = address
	}

	return loc
}

// standardAddress writes a Location's standard parts as one uppercase line,
// as USPS Publication 28 writes addresses.
func standardAddress(loc *contact.Location) string {
	join := func(sep string, s ...string) string {
		var out []string
		for _, v := range s {
			if v != "" {
				out = append(out, v)
			}
		}

		return strings.Join(out, sep)
	}

	place := join(" ", loc.BuildingNumber, loc.StreetName, loc.Unit)
	if loc.StreetName == "" {
		place = join(" ", cleanAddressPart(loc.Building), loc.BuildingNumber, loc.Unit)
	}
	if place == "" && loc.POBox == "" && loc.City == "" && loc.PostalCode == "" {
		return ""
	}

	return strings.ToUpper(join(", ", place, loc.POBox, loc.City,
		join(" ", loc.Province, loc.PostalCode), loc.Country))
}

func postalServerParseAddress(address string) ([]parsedComponent, error) {
	if !isPostalServerAvailable() {
		return nil, errors.New("libpostal is not available")
	}

	reqJSON, err := json.Marshal(parseRequest{Address: address})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, amasshttp.DefaultClient, &amasshttp.Request{
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if resp, err := amasshttp.RequestWebPage(ctx, amasshttp.DefaultClient, &amasshttp.Request{
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
