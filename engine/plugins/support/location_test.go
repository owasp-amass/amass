// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"strings"
	"testing"
)

// parts turns "label=value|label=value" into the parts libpostal returns.
func parts(s string) []parsedComponent {
	var out []parsedComponent
	for _, p := range strings.Split(s, "|") {
		label, value, _ := strings.Cut(p, "=")
		out = append(out, parsedComponent{Label: label, Value: value})
	}

	return out
}

// The same place written different ways is one Location.
func TestLocationFromPartsSamePlace(t *testing.T) {
	want := "110 8TH ST, TROY, NY 12180, US"
	for address, p := range map[string]string{
		"110 8th Street Troy NY 12180-3590 United States": "house_number=110|road=8th street|city=troy|" +
			"state=ny|postcode=12180-3590|country=united states",
		"110 8th Street Troy NY 12180 US": "house_number=110|road=8th street|city=troy|state=ny|" +
			"postcode=12180|country=us",
		"110 8th St Troy NY 12180 United States": "house_number=110|road=8th st|city=troy|state=ny|" +
			"postcode=12180|country=united states",
		"110 Eighth St, Troy, NY 12180, USA": "house_number=110|road=eighth st|city=troy|state=ny|" +
			"postcode=12180|country=usa",
		"Voorhees Computing Center 110 Eighth Street Troy NY 12180 United States": "house=voorhees computing center|" +
			"house_number=110|road=eighth street|city=troy|state=ny|postcode=12180|country=united states",
		"110 Eighth Street, Troy, New York 12180, USA": "house_number=110|road=eighth street|city=troy|" +
			"state=new york|postcode=12180|country=usa",
	} {
		loc := locationFromParts(address, parts(p))
		if loc.Address != want {
			t.Errorf("%q gave %q, want %q", address, loc.Address, want)
		}
		if loc.StreetName != "8th st" || loc.PostalCode != "12180" || loc.Country != "US" || loc.Province != "NY" {
			t.Errorf("%q gave parts %+v", address, loc)
		}
	}
}

// Different places stay different Locations.
func TestLocationFromPartsDifferentPlaces(t *testing.T) {
	a := locationFromParts("", parts("house=vcc|unit=room 308|house_number=110|road=8th street|city=troy|"+
		"state=ny|postcode=12180-3590|country=usa"))
	b := locationFromParts("", parts("house=vcc|unit=room 314|house_number=110|road=8th street|city=troy|"+
		"state=ny|postcode=12180|country=usa"))
	if a.Address != "110 8TH ST RM 308, TROY, NY 12180, US" {
		t.Errorf("room 308 gave %q", a.Address)
	}
	if a.Address == b.Address {
		t.Errorf("rooms 308 and 314 are both %q", a.Address)
	}

	// Without a street, the building names the place.
	c := locationFromParts("", parts("house=vcc|unit=room 314|city=troy|state=ny|country=usa"))
	if c.Address != "VCC RM 314, TROY, NY, US" {
		t.Errorf("a building without a street gave %q", c.Address)
	}
}

func TestStandardStreet(t *testing.T) {
	for street, want := range map[string]string{
		"north main street":      "n main st",
		"main street north":      "main st n",
		"north avenue":           "north ave",
		"west":                   "west",
		"Fifth Ave.":             "5th ave",
		"south boulevard south":  "south blvd s",
		"broadway":               "broadway",
		"avenue of the americas": "avenue of the americas",
	} {
		if got := standardStreet(street, "US"); got != want {
			t.Errorf("%q gave %q, want %q", street, got, want)
		}
	}

	// Words are standardized only for the countries whose forms are known.
	if got := standardStreet("Rue de la Paix", "FR"); got != "rue de la paix" {
		t.Errorf("a French street gave %q", got)
	}
}

func TestStandardUnit(t *testing.T) {
	for unit, want := range map[string]string{
		"Suite 200":  "ste 200",
		"ste #200":   "ste 200",
		"suite# 200": "ste 200",
		"#200":       "# 200",
		"Floor 3":    "fl 3",
	} {
		if got := standardUnit(unit, "US"); got != want {
			t.Errorf("%q gave %q, want %q", unit, got, want)
		}
	}
}

func TestStandardPOBoxAndPostcode(t *testing.T) {
	for box, want := range map[string]string{
		"P.O. Box 123":        "po box 123",
		"post office box 123": "po box 123",
		"PO Box 123":          "po box 123",
		"box 123":             "po box 123",
	} {
		if got := standardPOBox(box, "US"); got != want {
			t.Errorf("%q gave %q, want %q", box, got, want)
		}
	}

	for code, want := range map[[2]string]string{
		{"12180-3590", "US"}: "12180",
		{"12180", "US"}:      "12180",
		{"k1a-0b1", "CA"}:    "K1A 0B1",
		{"SW1A 1AA", "GB"}:   "SW1A 1AA",
	} {
		if got := standardPostcode(code[0], code[1]); got != want {
			t.Errorf("%q in %s gave %q, want %q", code[0], code[1], got, want)
		}
	}
}

// Without the parts that name a place, the address given is kept.
func TestLocationFromPartsKeepsUnparsedAddress(t *testing.T) {
	if loc := locationFromParts("Somewhere", parts("country=usa")); loc.Address != "Somewhere" {
		t.Errorf("an address with only a country gave %q", loc.Address)
	}
}
