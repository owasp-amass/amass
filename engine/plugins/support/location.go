// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"github.com/owasp-amass/amass/v5/internal/libpostal"
	"github.com/owasp-amass/open-asset-model/contact"
)

func StreetAddressToLocation(address string) *contact.Location {
	if address == "" {
		return nil
	}

	loc := &contact.Location{Address: address}
	parts, err := libpostal.ParseAddress(loc.Address)
	if err != nil {
		return nil
	}

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
			loc.Country = part.Value
		case "suburb":
			fallthrough
		case "city_district":
			if s := part.Value; s != "" {
				loc.Locality = s
			}
		}
	}
	return loc
}
