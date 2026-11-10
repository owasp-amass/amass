// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"testing"

	"github.com/miekg/dns"
)

func TestTXTDataConcatenatesStrings(t *testing.T) {
	rr := &dns.TXT{Txt: []string{"v=spf1 include:_spf.goo", "gle.com ~all"}}
	if got := txtData(rr); got != "v=spf1 include:_spf.google.com ~all" {
		t.Errorf("txtData = %q", got)
	}
	if got := txtData(&dns.TXT{Txt: []string{"google-site-verification=abc"}}); got != "google-site-verification=abc" {
		t.Errorf("txtData = %q", got)
	}
}
