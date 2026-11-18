// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"testing"

	"github.com/owasp-amass/open-asset-model/contact"
)

func TestRecordAtAddressConfirmsStreet(t *testing.T) {
	seed := &contact.Location{StreetName: "Oak Drive", BuildingNumber: "13", City: "Hamilton"}

	rec := &LEIRecord{}
	rec.Attributes.Entity.LegalAddress = LEIAddress{AddressLines: []string{"13 Oak Drive"}, City: "Hamilton"}
	if !recordAtAddress(seed, rec) {
		t.Error("a record on the same street and number was not matched")
	}

	// Same city, different street: must not match (the city-level filter alone
	// is not enough to attach an organization).
	other := &LEIRecord{}
	other.Attributes.Entity.LegalAddress = LEIAddress{AddressLines: []string{"500 Elm Street"}, City: "Hamilton"}
	if recordAtAddress(seed, other) {
		t.Error("a record on a different street in the same city was matched")
	}

	// Same street, different house number: must not match when the seed names
	// a number.
	wrongNum := &LEIRecord{}
	wrongNum.Attributes.Entity.HeadquartersAddress = LEIAddress{AddressLines: []string{"99 Oak Drive"}}
	if recordAtAddress(seed, wrongNum) {
		t.Error("a record with a different house number on the street was matched")
	}
}

func TestAddressLineMatchesUsesHeadquartersAndNumberField(t *testing.T) {
	// The street can sit in the address line while the number is in the
	// dedicated AddressNumber field.
	seed := &contact.Location{StreetName: "Main St", BuildingNumber: "7"}
	ad := &LEIAddress{AddressLines: []string{"Main St"}, AddressNumber: "7"}
	if !addressLineMatches(seed, ad) {
		t.Error("a split street/number address was not matched")
	}

	// With no street on the seed there is nothing to confirm.
	if addressLineMatches(&contact.Location{}, ad) {
		t.Error("an empty seed street matched")
	}
}
