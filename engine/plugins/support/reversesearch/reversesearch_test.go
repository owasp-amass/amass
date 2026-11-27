// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package reversesearch

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestQueryBuilders(t *testing.T) {
	cases := []struct {
		name          string
		fn            func(string, string) (string, bool)
		idType, value string
		want          string
		ok            bool
	}{
		{"shodan favicon", ShodanQuery, "favicon_mmh3", "-12345", "http.favicon.hash:-12345", true},
		{"shodan jarm", ShodanQuery, "JARM", "2ad2ad", "ssl.jarm:2ad2ad", true},
		{"shodan title unsupported", ShodanQuery, "http_title", "x", "", false},
		{"fofa favicon", FofaQuery, "favicon_mmh3", "-12345", `icon_hash="-12345"`, true},
		{"fofa jarm", FofaQuery, "JARM", "2ad2ad", `jarm="2ad2ad"`, true},
		{"zoomeye favicon", ZoomEyeQuery, "favicon_mmh3", "-12345", `iconhash:"-12345"`, true},
		{"zoomeye jarm", ZoomEyeQuery, "JARM", "2ad2ad", `jarm:"2ad2ad"`, true},
		{"censys jarm", CensysQuery, "JARM", "2ad2ad", `services.jarm.fingerprint:"2ad2ad"`, true},
		{"censys favicon_md5", CensysQuery, "favicon_md5", "abc", `services.http.response.favicons.md5_hash:"abc"`, true},
		// Censys does not index the mmh3 favicon Amass stores.
		{"censys mmh3 unsupported", CensysQuery, "favicon_mmh3", "-12345", "", false},
	}
	for _, c := range cases {
		got, ok := c.fn(c.idType, c.value)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestFofaQueryBase64(t *testing.T) {
	enc, ok := FofaQueryBase64("favicon_mmh3", "-12345")
	if !ok {
		t.Fatal("favicon should be supported")
	}
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != `icon_hash="-12345"` {
		t.Errorf("decoded = %q", dec)
	}
	if _, ok := FofaQueryBase64("http_title", "x"); ok {
		t.Error("an unsupported id_type should not build a query")
	}
}

func TestParseShodan(t *testing.T) {
	data := []byte(`{"matches":[{"ip_str":"192.0.2.1","port":443},{"ip_str":"192.0.2.2","port":8443},{"ip_str":"192.0.2.1","port":443}]}`)
	got, err := ParseShodan(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []Hit{{"192.0.2.1", 443}, {"192.0.2.2", 8443}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseCensys(t *testing.T) {
	data := []byte(`{"result":{"hits":[{"ip":"192.0.2.3","services":[{"port":443},{"port":80}]},{"ip":"192.0.2.4","services":[]}]}}`)
	got, err := ParseCensys(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []Hit{{"192.0.2.3", 443}, {"192.0.2.3", 80}, {"192.0.2.4", 0}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseFofa(t *testing.T) {
	data := []byte(`{"error":false,"results":[["192.0.2.5","443"],["192.0.2.6","8080"],["",""],["192.0.2.5","443"]]}`)
	got, err := ParseFofa(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []Hit{{"192.0.2.5", 443}, {"192.0.2.6", 8080}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseZoomEye(t *testing.T) {
	data := []byte(`{"matches":[{"ip":"192.0.2.7","portinfo":{"port":443}},{"ip":"192.0.2.8","portinfo":{"port":22}}]}`)
	got, err := ParseZoomEye(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []Hit{{"192.0.2.7", 443}, {"192.0.2.8", 22}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := ParseShodan([]byte("not json")); err == nil {
		t.Error("expected an error on malformed JSON")
	}
}
