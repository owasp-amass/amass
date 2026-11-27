// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestFindLookalikes(t *testing.T) {
	g := graphtest.ServicesFixture()
	fqdn := func(name string) {
		g.Assets[name] = graph.Asset{ID: name, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
	}
	record := func(from, to, typ string, rr int) {
		fqdn(to)
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + to, FromID: from, ToID: to, Label: "dns_record",
			Type: typ, Content: map[string]any{"header": map[string]any{"rr_type": rr}}})
	}

	// A deletion typo on another party's name servers that receives mail.
	fqdn("owsp.org")
	record("owsp.org", "ns1.parking.example", "BasicDNSRelation", 2)
	record("owsp.org", "mx.parking.example", "PrefDNSRelation", 15)
	// Another suffix, delegated to the subject's own name servers.
	fqdn("owasp.com")
	record("owasp.com", "ns1.owasp.org", "BasicDNSRelation", 2)
	// An unrelated stored name that is no typo.
	fqdn("example.org")

	r, err := FindLookalikes(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Lookalikes) != 2 || r.Checked == 0 {
		t.Fatalf("lookalikes %+v (checked %d)\n%s", r.Lookalikes, r.Checked, r.Text())
	}

	first, second := r.Lookalikes[0], r.Lookalikes[1]
	if first.Domain != "owsp.org" || first.Owner != LookalikeOther || !first.Mail || first.Imitates != "owasp.org" {
		t.Errorf("first %+v", first)
	}
	if second.Domain != "owasp.com" || second.Owner != LookalikeOwnDNS || second.Mail {
		t.Errorf("second %+v", second)
	}

	text := r.Text()
	for _, want := range []string{"Not tied to it (1)", "owsp.org (like owasp.org): receives mail",
		"On its own name servers", "not necessarily hostile"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	if facts := strings.Join(r.Facts(), "\n"); !strings.Contains(facts, "lookalike_mail owsp.org") {
		t.Errorf("facts:\n%s", facts)
	}
}
