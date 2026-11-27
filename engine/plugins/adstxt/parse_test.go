// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package adstxt

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseAdsTxt(t *testing.T) {
	data := `# ads.txt for example.com
contact=ads@example.com
OWNERDOMAIN=example.com
google.com, pub-1234567890123456, DIRECT, f08c47fec0942fa0
Google.com, pub-1234567890123456, DIRECT # repeated
appnexus.com, 1234, RESELLER, f5ab79cb980f11d1
www.rubiconproject.com, 5678 , direct
not a line
, 99, DIRECT
`
	got := parseAdsTxt(data, 10)
	want := []account{{"google.com", "pub-1234567890123456"}, {"rubiconproject.com", "5678"}}
	if !reflect.DeepEqual(got.accounts, want) || got.ownerDomain != "example.com" ||
		!reflect.DeepEqual(got.contacts, []string{"ads@example.com"}) {
		t.Fatalf("parseAdsTxt = %+v, want %v and owner example.com", got, want)
	}
	if got := parseAdsTxt(data, 1); len(got.accounts) != 1 || got.ownerDomain != "example.com" {
		t.Fatalf("max not applied, or the owner was lost: %+v", got)
	}
	if k := want[0].key(); k != "google.com:pub-1234567890123456" {
		t.Fatalf("key = %q", k)
	}
}

func TestParseSellers(t *testing.T) {
	data := `{"version":"1.0","sellers":[
		{"seller_id":"pub-1","name":"Example Media Inc.","domain":"example.com","seller_type":"PUBLISHER"},
		{"seller_id":5678,"name":"Sales House","domain":"saleshouse.com","seller_type":"INTERMEDIARY"},
		{"seller_id":"pub-2","is_confidential":1,"seller_type":"PUBLISHER"},
		{"seller_id":"pub-3","is_confidential":true,"seller_type":"PUBLISHER"},
		{"name":"no id"}]}`
	m, err := parseSellers(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["pub-1"].Domain != "example.com" || m["5678"].Type != "INTERMEDIARY" {
		t.Fatalf("parseSellers = %+v", m)
	}
}
