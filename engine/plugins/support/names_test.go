// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	"github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// The graph settles what a name's words do not: a name an organization is
// stored under is that organization's.
func TestNameKindReadsTheGraph(t *testing.T) {
	sess := plugintest.NewSession(t)

	kind, _, p := NameKind(sess, "Ada Lovelace", nil, []string{"ada@example.com"})
	if kind != semantics.NameKindPerson || p == nil || p.FamilyName != "Lovelace" {
		t.Errorf("Ada Lovelace: %s %+v", kind, p)
	}
	if kind, _, _ = NameKind(sess, "Morgan Stanley", nil, nil); kind != semantics.NameKindPerson {
		t.Errorf("Morgan Stanley with nothing stored: %s", kind)
	}

	sess.Asset(t, &oamorg.Organization{ID: "ms:1", Name: semantics.OrgNameKey("Morgan Stanley")})
	if kind, why, p := NameKind(sess, "Morgan Stanley", nil, nil); kind != semantics.NameKindOrganization ||
		p != nil {
		t.Errorf("Morgan Stanley once stored: %s %v", kind, why)
	}

	cr := sess.Asset(t, &contact.ContactRecord{DiscoveredAt: "https://example.net/whois"})
	KeepUncertainName(context.Background(), sess, cr, "person", " Sarah Church ", nil, nil)
	tags, err := sess.DB().FindEntityTags(context.Background(), cr, time.Time{}, graph.UncertainNameProp)
	if err != nil || len(tags) != 1 || tags[0].Property.Value() != "Sarah Church" {
		t.Errorf("the uncertain name kept: %v, %v", tags, err)
	}

	j := ReviewJournal(sess, func(string) (string, bool) { return "", false })
	if j == nil {
		t.Fatal("no review journal with attribution on")
	}
	names, err := j.NameKindEntries()
	if err != nil || len(names) != 1 || names[0].Proposal.Name != "Sarah Church" ||
		names[0].Proposal.RecordID != cr.ID || names[0].Proposal.Label != "person" {
		t.Errorf("the name proposal: %+v, %v", names, err)
	}
}

// A source that lists people keeps a name its words leave uncertain, but not
// one they say is an organization or a role.
func TestListedPerson(t *testing.T) {
	for raw, want := range map[string]bool{"Ada Lovelace": true, "Sarah Church": true, "Morgan Stanley": true,
		"OWASP Foundation": false, "MarkMonitor, Inc.": false, "Domain Administrator": false, "Microsoft": false} {
		if got := ListedPerson(raw) != nil; got != want {
			t.Errorf("%q: %v, want %v", raw, got, want)
		}
	}
}
