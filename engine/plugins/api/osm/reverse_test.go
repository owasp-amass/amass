// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package osm

import (
	"strings"
	"testing"

	"github.com/owasp-amass/open-asset-model/contact"
)

func TestDigitsOnly(t *testing.T) {
	if got := digitsOnly("+1 (315) 228-1000"); got != "13152281000" {
		t.Errorf("digitsOnly = %q, want 13152281000", got)
	}
	if got := digitsOnly("no digits"); got != "" {
		t.Errorf("digitsOnly = %q, want empty", got)
	}
}

func TestPhoneRegexMatchesAnySeparators(t *testing.T) {
	re := phoneRegex("+13152281000")
	// Every digit in order, separated by a non-digit class.
	if !strings.HasPrefix(re, "1[^0-9]*3[^0-9]*1[^0-9]*5") {
		t.Errorf("regex = %q", re)
	}
	if phoneRegex("no digits") != "" {
		t.Error("a number with no digits produced a pattern")
	}
}

func TestFeatureHasPhoneConfirmsOnDigits(t *testing.T) {
	el := &element{Tags: map[string]string{"contact:phone": "+1-315-228-1000; +1 315 228 7000"}}

	if !featureHasPhone(el, "13152281000") {
		t.Error("an exact number, differently formatted, was not matched")
	}
	if !featureHasPhone(el, "13152287000") {
		t.Error("the second listed number was not matched")
	}
	if featureHasPhone(el, "13152289999") {
		t.Error("a number the feature does not carry was matched")
	}
}

func TestFeatureAtAddressIsConservative(t *testing.T) {
	loc := &contact.StreetAddress{StreetName: "Oak Drive", BuildingNumber: "13"}

	same := &element{Tags: map[string]string{"addr:street": "Oak Drive", "addr:housenumber": "13"}}
	if !featureAtAddress(same, loc) {
		t.Error("the same street and number was not matched")
	}

	otherNumber := &element{Tags: map[string]string{"addr:street": "Oak Drive", "addr:housenumber": "99"}}
	if featureAtAddress(otherNumber, loc) {
		t.Error("a different house number on the same street was matched")
	}

	otherStreet := &element{Tags: map[string]string{"addr:street": "Elm Street", "addr:housenumber": "13"}}
	if featureAtAddress(otherStreet, loc) {
		t.Error("a different street was matched")
	}
}

func TestAddressQueryKeysOnStreetAndNumber(t *testing.T) {
	q := addressQuery(&contact.StreetAddress{StreetName: "Oak Drive", BuildingNumber: "13", City: "Utica"})

	for _, want := range []string{`"addr:street"`, "Oak Drive", `"addr:housenumber"="13"`, `"addr:city"`} {
		if !strings.Contains(q, want) {
			t.Errorf("query %q missing %q", q, want)
		}
	}
}
