// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
)

func TestPerformQueryAnswersFromTheSessionResolvers(t *testing.T) {
	sess := plugintest.NewSession(t)
	fake := sess.DNS(t)
	fake.Add(t,
		"www.example.com. 300 IN A 192.0.2.10",
		"www.example.com. 300 IN TXT \"hello\"",
		"10.2.0.192.in-addr.arpa. 300 IN PTR www.example.com.",
	)

	rr, err := PerformQuery(sess.Ctx(), "www.example.com", dns.TypeA)
	if err != nil || len(rr) != 1 || rr[0].(*dns.A).A.String() != "192.0.2.10" {
		t.Fatalf("A answer = %v, %v", rr, err)
	}
	if fake.Asked(dns.TypeA, "www.example.com") == 0 {
		t.Errorf("the query did not reach the session's resolver: %v", fake.Queries())
	}

	if _, err := PerformQuery(sess.Ctx(), "nope.example.com", dns.TypeA); err != ErrNameDoesNotExist {
		t.Errorf("a missing name gave %v", err)
	}
	if _, err := PerformQuery(sess.Ctx(), "www.example.com", dns.TypeAAAA); err != ErrNoRecordOfThisType {
		t.Errorf("a missing record type gave %v", err)
	}

	// A PTR query takes the address and asks for its reverse name.
	rr, err = PerformQuery(sess.Ctx(), "192.0.2.10", dns.TypePTR)
	if err != nil || len(rr) != 1 || rr[0].(*dns.PTR).Ptr != "www.example.com." {
		t.Errorf("PTR answer = %v, %v", rr, err)
	}
}

func TestPerformQuerySuppressesWildcardAnswers(t *testing.T) {
	sess := plugintest.NewSession(t)
	fake := sess.DNS(t)
	fake.Add(t,
		"*.example.com. 300 IN A 192.0.2.99",
		"www.example.com. 300 IN A 192.0.2.10",
	)

	// A name answered only by the wildcard is not reported...
	if rr, err := PerformQuery(sess.Ctx(), "guessed.example.com", dns.TypeA); err == nil {
		t.Errorf("a wildcard answer was returned: %v", rr)
	}
	// ...but one with its own records is.
	if rr, err := PerformQuery(sess.Ctx(), "www.example.com", dns.TypeA); err != nil || len(rr) != 1 {
		t.Errorf("a name with its own record gave %v, %v", rr, err)
	}
	// A name a DNS record named is real, so its answer is kept even in a wildcard zone.
	if rr, err := PerformQueryNoWildcard(sess.Ctx(), "target.example.com", dns.TypeA); err != nil || len(rr) != 1 {
		t.Errorf("PerformQueryNoWildcard gave %v, %v", rr, err)
	}
}
