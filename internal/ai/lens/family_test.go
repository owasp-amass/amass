// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/aitest"
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

func TestNameVariant(t *testing.T) {
	generic := loadFamilyRules().GenericWords
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"university at albany", "university at albany state university of new york", true},
		{"suny at albany", "university at albany state university of new york", true},
		{"johns hopkins university", "the johns hopkins university", true},
		{"the johns hopkins medical institutions", "the johns hopkins university", false},
		{"university at buffalo", "university at albany state university of new york", false},
		{"state university", "university at albany state university of new york", false},
	} {
		if got := nameVariant(c.a, c.b, generic); got != c.want {
			t.Errorf("nameVariant(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// A company's family: its security unit (a registration contact) is a
// department; a vendor on a certificate with a unit word in its name is not;
// an organization sharing only generic words such as holdings or
// international is not an affiliate.
func TestFindOrganizationFamilyOfCompany(t *testing.T) {
	g := aitest.NewOrgGraph()
	a := func(id, typ string, content map[string]any) {
		g.Graph.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	cert := func(id, cn, org string) {
		a(id, "TLSCertificate", map[string]any{"subject_common_name": cn})
		a("cr-"+id, "ContactRecord", nil)
		g.Link(id, "cr-"+id, "subject_contact")
		g.Link("cr-"+id, org, "organization")
		if _, ok := g.Graph.Assets[cn]; !ok {
			a(cn, "FQDN", map[string]any{"name": cn})
			g.Link("acme.example", cn, "node")
		}
		g.Link(id, cn, "common_name")
	}

	g.Org("acme", "acme robotics holdings", "acme robotics holdings, inc.", "US-DE", "7")
	g.Org("secops", "acme security operations", "", "", "")
	g.Org("vendor", "global library services", "", "", "")
	g.Org("generic", "holdings international ltd", "", "", "")

	a("acme.example", "FQDN", map[string]any{"name": "acme.example"})
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("www%d.acme.example", i)
		a(name, "FQDN", map[string]any{"name": name})
		g.Link("acme.example", name, "node")
		cert(fmt.Sprintf("c%d", i), name, "acme")
	}
	cert("cv", "docs.acme.example", "vendor")
	cert("cg", "shop.acme.example", "generic")

	a("dr", "DomainRecord", map[string]any{"domain": "acme.example"})
	g.Link("acme.example", "dr", "registration")
	a("cr-sec", "ContactRecord", nil)
	g.Link("dr", "cr-sec", "technical_contact")
	g.Link("cr-sec", "secops", "organization")
	g.Graph.Assets["email:soc@acme.example"] = graph.Asset{ID: "email:soc@acme.example", Type: "Identifier",
		Key: "email:soc@acme.example", Content: map[string]any{"id": "soc@acme.example", "id_type": "email"}}
	g.Link("cr-sec", "email:soc@acme.example", "id")

	r, err := FindOrganizationFamily(context.Background(), g.Graph, g.Graph.Assets["acme.example"])
	if err != nil {
		t.Fatal(err)
	}
	if r.Main == nil || r.Main.ID != "acme" {
		t.Fatalf("main = %+v", r.Main)
	}

	got := map[string]string{}
	for _, m := range r.Members {
		got[m.Organization.ID] = m.Relation
	}
	want := map[string]string{"acme": FamilySame, "secops": FamilyDepartment, "vendor": FamilyOther,
		"generic": FamilyOther}
	for id, rel := range want {
		if got[id] != rel {
			t.Errorf("%s: relation %q, want %q (members %v)", id, got[id], rel, got)
		}
	}
}

func TestNameMatchesLabel(t *testing.T) {
	rules := loadFamilyRules()
	stop := abbreviationStopWords()
	for _, c := range []struct {
		name, label string
		want        bool
	}{
		{"automattic", "automattic", true},
		{"national grid usa service company", "nationalgridus", true},
		{"national aeronautics and space administration", "nasa", true},
		{"northrop grumman corporation", "ngc", true},
		{"mohawk valley community college", "mvcc", true},
		{"utica university", "utica", true},
		{"salesforce", "nationalgridus", false},
		// A generic leading word alone does not spell a label.
		{"national grid", "national", false},
		// A short name only matches a label it equals.
		{"ngs", "ngsolutions", false},
		{"rochester institute of technology", "rit", true},
		{"national grid", "ngrid", true},
		{"national grid", "grid", false},
	} {
		if got := nameMatchesLabel(strings.Fields(c.name), c.label, rules.GenericWords, stop); got != c.want {
			t.Errorf("nameMatchesLabel(%q, %q) = %v, want %v", c.name, c.label, got, c.want)
		}
	}
}

func TestRenamed(t *testing.T) {
	s := &familySearch{rules: loadFamilyRules()}
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"utica college", "utica university", true},
		{"the utica college", "utica university", true},
		{"johns hopkins university", "johns hopkins hospital", false},
		{"utica college", "utica college", false},
		{"utica university", "syracuse university", false},
	} {
		if got := s.renamed(c.a, c.b); got != c.want {
			t.Errorf("renamed(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
