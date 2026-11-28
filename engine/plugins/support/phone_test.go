// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"testing"

	"github.com/nyaruka/phonenumbers"
)

// example is libphonenumber's own example number of a type in a region.
func example(t *testing.T, region string, typ phonenumbers.PhoneNumberType) string {
	t.Helper()
	num := phonenumbers.GetExampleNumberForType(region, typ)
	if num == nil {
		t.Fatalf("no %s example of type %v", region, typ)
	}
	return phonenumbers.Format(num, phonenumbers.E164)
}

func TestPhoneDetails(t *testing.T) {
	if lt, region := PhoneDetails(example(t, "GB", phonenumbers.FIXED_LINE)); lt != "fixed_line" || region == "" {
		t.Errorf("a UK fixed line gave %q, %q", lt, region)
	}
	if lt, _ := PhoneDetails(example(t, "GB", phonenumbers.MOBILE)); lt != "mobile" {
		t.Errorf("a UK mobile gave %q", lt)
	}
	if lt, _ := PhoneDetails(example(t, "US", phonenumbers.TOLL_FREE)); lt != "toll_free" {
		t.Errorf("a US toll-free number gave %q", lt)
	}
	if lt, region := PhoneDetails("not a number"); lt != "" || region != "" {
		t.Errorf("garbage gave %q, %q", lt, region)
	}
}

// The country is the number's own, not the hint it was parsed with.
func TestPhoneCountry(t *testing.T) {
	uk := example(t, "GB", phonenumbers.FIXED_LINE)
	if p := PhoneToOAMPhone(uk, "", "US"); p == nil || p.CountryAbbrev != "GB" || p.CountryCode != 44 {
		t.Errorf("a UK number with a US hint = %+v", p)
	}
	if p := PhoneToOAMPhone(uk, "", ""); p == nil || p.CountryAbbrev != "GB" {
		t.Errorf("a UK number with no hint = %+v", p)
	}
}
