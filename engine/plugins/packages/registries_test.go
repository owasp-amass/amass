// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"reflect"
	"testing"
)

// fp is the footprint the registry tests search with: the domain searched
// for and another domain in scope.
var fp = support.Footprint{"example.com", "example-labs.org"}

func TestParseNuGetSearch(t *testing.T) {
	got := parseNuGetSearch([]byte(`{"data":[
		{"id":"Example.Client","projectUrl":"https://github.com/example/client","owners":["example"]},
		{"id":"Example.Sdk","projectUrl":"https://sdk.example-labs.org/","owners":"exampleteam"},
		{"id":"Other","projectUrl":"https://other.example.net/","owners":[]}]}`), fp)
	if len(got) != 1 || got[0].purl != "pkg:nuget/Example.Sdk" || got[0].namespace != "~exampleteam" ||
		got[0].domain != "example-labs.org" || len(got[0].urls) != 1 || got[0].urls[0].role != RoleProject {
		t.Fatalf("parseNuGetSearch = %+v", got)
	}
}

func TestParseCratesSearch(t *testing.T) {
	got := parseCratesSearch([]byte(`{"crates":[
		{"name":"example-core","homepage":null,"documentation":"https://docs.example.com/core",
			"repository":"https://github.com/example/core","updated_at":"2026-01-02T03:04:05.000000+00:00"},
		{"name":"lookalike","homepage":"https://example.com.evil.org","repository":"https://github.com/x/y"}]}`), fp)
	if len(got) != 1 || got[0].purl != "pkg:cargo/example-core" || got[0].namespace != "" ||
		got[0].domain != "example.com" || got[0].updated == 0 || len(got[0].urls) != 2 ||
		got[0].urls[1].role != RoleRepository {
		t.Fatalf("parseCratesSearch = %+v", got)
	}
}

func TestParseRubyGemsSearch(t *testing.T) {
	got := parseRubyGemsSearch([]byte(`[
		{"name":"example","homepage_uri":"https://www.example.com","source_code_uri":"https://github.com/example/rb"},
		{"name":"examplex","homepage_uri":"https://github.com/someone/examplex"}]`), fp)
	if len(got) != 1 || got[0].purl != "pkg:gem/example" || got[0].domain != "example.com" || len(got[0].urls) != 2 {
		t.Fatalf("parseRubyGemsSearch = %+v", got)
	}
}

func TestParsePackagist(t *testing.T) {
	names := parsePackagistSearch([]byte(`{"results":[{"name":"example/api-client"},{"name":"bad"}],"total":2}`))
	if !reflect.DeepEqual(names, []string{"example/api-client"}) {
		t.Fatalf("parsePackagistSearch = %v", names)
	}

	meta := []byte(`{"packages":{"example/api-client":[{"homepage":"https://github.com/example/api-client",
		"time":"2026-02-03T04:05:06+00:00","source":{"url":"https://github.com/example/api-client.git"},
		"authors":[{"name":"Dev","email":"Dev@Example-Labs.org"},{"name":"Other","email":"other@gmail.com"}]}]}}`)
	k, ok := parsePackagistMetadata(meta, "example/api-client", fp)
	if !ok || k.namespace != "example" || k.purl != "pkg:composer/example/api-client" || k.domain != "example-labs.org" ||
		!reflect.DeepEqual(k.maintainers, []string{"dev@example-labs.org"}) || k.updated == 0 || len(k.urls) != 2 {
		t.Fatalf("parsePackagistMetadata = %+v, %v", k, ok)
	}

	// nothing in the footprint: not kept
	unrelated := []byte(`{"packages":{"x/y":[{"homepage":"https://x.example.net",` +
		`"authors":[{"email":"a@x.example.net"}]}]}}`)
	if _, ok := parsePackagistMetadata(unrelated, "x/y", fp); ok {
		t.Error("a package tied to nothing in the footprint was kept")
	}
}

func TestOwners(t *testing.T) {
	if got := crateOwner([]byte(`{"users":[{"login":"example-dev","kind":"user"},{"login":"x"}]}`)); got != "example-dev" {
		t.Errorf("crateOwner = %q", got)
	}
	if got := gemOwner([]byte(`[{"id":1,"handle":"exampledev"}]`)); got != "exampledev" {
		t.Errorf("gemOwner = %q", got)
	}
	if crateOwner([]byte(`{"users":[]}`)) != "" || gemOwner([]byte(`<html>`)) != "" {
		t.Error("an empty or unreadable owners answer gave an owner")
	}
}
