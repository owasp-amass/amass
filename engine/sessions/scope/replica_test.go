// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/coord"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// applyAll gives the scope every record of the topic, as the session's follower
// would.
func applyAll(t *testing.T, s *Scope, topic *coord.Topic) {
	t.Helper()
	recs, err := topic.Read(0)
	if err != nil {
		t.Fatal(err)
	}
	s.Apply(recs)
}

// The workers of a job see the entries each adds, once, with the ones an
// admission added still standing as admitted; another job's entries and a
// worker's own are not applied again.
func TestScopeIsSharedByTheJobsWorkers(t *testing.T) {
	topic := &coord.Topic{Store: &coord.FakeStore{}, Name: "work"}
	a, b := New(nil).(*Scope), New(nil).(*Scope)
	other := New(nil).(*Scope)
	a.Replicate(topic, nil, "job", "a")
	b.Replicate(topic, nil, "job", "b")
	other.Replicate(topic, nil, "job-2", "c")

	if !a.AddDomain("Example.com") || !a.AddCIDR("192.0.2.0/24") || !a.AddASN(64500) {
		t.Fatal("the entries were not added")
	}
	if !a.Add(&oamreg.DomainRecord{Domain: "example.org"}) {
		t.Fatal("the domain record's entry was not added")
	}
	if !a.addEntry(&oamorg.Organization{ID: "acme", Name: "Acme Corporation"}, true, true) {
		t.Fatal("the admitted organization was not added")
	}
	other.AddDomain("unrelated.com")
	if n := len(topic.Store.(*coord.FakeStore).Records()); n != 6 {
		t.Fatalf("%d records, want one per new entry", n)
	}
	if a.AddDomain("example.com") {
		t.Fatal("an entry was added twice")
	}

	applyAll(t, b, topic)
	if got := b.Domains(); len(got) != 2 {
		t.Errorf("b has the domains %v", got)
	}
	if len(b.CIDRs()) != 1 || len(b.ASNs()) != 1 || len(b.Organizations()) != 1 {
		t.Errorf("b has %v, %v and %v", b.CIDRs(), b.ASNs(), b.Organizations())
	}
	if st := b.Standing(&oamorg.Organization{ID: "acme", Name: "Acme Corporation"}); st != et.StandingAdmitted {
		t.Errorf("the admitted organization stands %v for b", st)
	}
	if st := b.Standing(&oamdns.FQDN{Name: "www.example.com"}); st != et.InScope {
		t.Errorf("a name under a shared domain stands %v for b", st)
	}

	// a worker's own records and another job's are not applied
	applyAll(t, a, topic)
	if got := a.Domains(); len(got) != 2 {
		t.Errorf("a has the domains %v", got)
	}
	// b's new entries reach a, and b does not share what it applied
	b.AddDomain("example.net")
	applyAll(t, a, topic)
	if len(a.Domains()) != 3 {
		t.Errorf("a has the domains %v", a.Domains())
	}
	if n := len(topic.Store.(*coord.FakeStore).Records()); n != 7 {
		t.Errorf("%d records; applied entries were shared again", n)
	}
}
