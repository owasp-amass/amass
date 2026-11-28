// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package packages

import (
	"reflect"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
)

func TestMavenGroup(t *testing.T) {
	for apex, want := range map[string]string{"example.com": "com.example", "Example.co.uk.": "uk.co.example"} {
		if got := mavenGroup(apex); got != want {
			t.Errorf("mavenGroup(%q) = %q, want %q", apex, got, want)
		}
	}
}

func TestParseMavenSearch(t *testing.T) {
	data := []byte(`{"response":{"numFound":3,"docs":[
		{"id":"com.example:core","g":"com.example","a":"core","latestVersion":"2.1.0","timestamp":1700000000000},
		{"id":"com.example.cloud:sdk","g":"com.example.cloud","a":"sdk","latestVersion":"1.0","timestamp":1710000000000},
		{"id":"com.examplex:other","g":"com.examplex","a":"other","latestVersion":"1.0","timestamp":1720000000000}]}}`)
	got, err := parseMavenSearch(data, "com.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].purl != "pkg:maven/com.example/core" || got[0].version != "2.1.0" ||
		got[0].title != "com.example:core" || got[1].namespace != "com.example.cloud" {
		t.Fatalf("parseMavenSearch = %+v", got)
	}
	if n := newest(got, 1); len(n) != 1 || n[0].name != "sdk" {
		t.Fatalf("newest = %+v", n)
	}
}

func TestParsePOM(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <url>https://docs.example.io/core</url>
  <organization><name>Example, Inc.</name><url>https://www.example-corp.com</url></organization>
  <scm><url>https://github.com/example/core</url></scm>
  <developers><developer><url>${project.url}</url></developer></developers>
</project>`)
	urls, org := parsePOM(data)
	want := []pkgURL{{"https://docs.example.io/core", RoleProject}, {"https://www.example-corp.com", RoleOrganization},
		{"https://github.com/example/core", RoleRepository}}
	if org != "Example, Inc." || !reflect.DeepEqual(urls, want) {
		t.Fatalf("parsePOM = %v, %q", urls, org)
	}
	if urls, _ := parsePOM([]byte(`<project><url>${project.parent.url}</url></project>`)); len(urls) != 0 {
		t.Fatalf("an unresolved placeholder was kept: %v", urls)
	}
}

func TestParseNPMSearch(t *testing.T) {
	data := []byte(`{"objects":[
		{"package":{"name":"@example/widgets","scope":"example","date":"2026-01-02T03:04:05.000Z",
			"links":{"homepage":"https://widgets.example.dev","repository":"git+https://github.com/example/widgets.git"},
			"publisher":{"username":"jdoe","email":"jdoe@example.com"},
			"maintainers":[{"username":"jdoe","email":"jdoe@example.com"},{"username":"x","email":"x@gmail.com"}]}},
		{"package":{"name":"example-cli","scope":"unscoped","date":"2025-01-02T03:04:05.000Z",
			"links":{"homepage":"https://www.example.com/cli"},
			"publisher":{"username":"builder","email":"builder@gmail.com"},"maintainers":[]}},
		{"package":{"name":"unrelated","scope":"unscoped",
			"links":{"homepage":"https://elsewhere.org"},
			"publisher":{"username":"someone","email":"someone@elsewhere.org"}}}]}`)
	got, err := parseNPMSearch(data, support.Footprint{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("parseNPMSearch = %+v", got)
	}
	w := got[0]
	if w.namespace != "@example" || w.name != "widgets" || w.title != "@example/widgets" ||
		w.purl != "pkg:npm/%40example/widgets" || !reflect.DeepEqual(w.maintainers, []string{"jdoe@example.com"}) ||
		len(w.urls) != 2 || w.urls[1].role != RoleRepository || w.domain != "example.com" {
		t.Errorf("scoped package = %+v", w)
	}
	c := got[1]
	if c.namespace != "~builder" || c.purl != "pkg:npm/example-cli" || len(c.maintainers) != 0 ||
		c.domain != "example.com" {
		t.Errorf("homepage-anchored package = %+v", c)
	}
}

func TestPackageURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://www.example-corp.com":            "https://www.example-corp.com",
		"git+https://docs.example.io/core#readme": "https://docs.example.io/core",
		"https://github.com/example/core":         "https://github.com/example/core",
		"git@github.com:example/core.git":         "",
		"ftp://example.com/pkg":                   "",
	} {
		got := ""
		if u := packageURL(raw); u != nil {
			got = u.Raw
		}
		if got != want {
			t.Errorf("packageURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

// tiedURLs keeps the URLs given and names the footprint domain of the first
// one in it.
func TestTiedURLs(t *testing.T) {
	f := support.Footprint{"example.com", "example-labs.org"}
	urls, domain := tiedURLs(f, pkgURL{"", RoleHomepage}, pkgURL{"https://github.com/x/y", RoleRepository},
		pkgURL{"https://docs.example-labs.org", RoleProject})
	if len(urls) != 2 || domain != "example-labs.org" {
		t.Errorf("tiedURLs = %v, %q", urls, domain)
	}
}

func TestNamespacePage(t *testing.T) {
	for _, c := range []struct{ registry, namespace, want string }{
		{"npm", "@example", "https://www.npmjs.com/org/example"},
		{"npm", "~builder", "https://www.npmjs.com/~builder"},
		{"maven", "com.example", "https://central.sonatype.com/namespace/com.example"},
		{"composer", "example", "https://packagist.org/packages/example/"},
		{"nuget", "~builder", "https://www.nuget.org/profiles/builder"},
		{"pypi", "example", ""},
	} {
		if got := (pkg{registry: c.registry, namespace: c.namespace}).namespacePage(); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.registry, c.namespace, got, c.want)
		}
	}
}
