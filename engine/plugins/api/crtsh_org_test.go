// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import "testing"

// Shaped exactly like a real crt.sh ?O= response: the domain is in common_name
// and name_value echoes the matched subject organization.
func TestCrtshOrgCerts(t *testing.T) {
	body := `[
      {"common_name":"app01.sunyit.edu","name_value":"SUNY Polytechnic Institute","serial_number":"0fa16da02499d58ff063ad7398b10de0"},
      {"common_name":"*.sunyit.edu","name_value":"SUNY Polytechnic Institute","serial_number":"aa11"},
      {"common_name":"app01.sunyit.edu","name_value":"SUNY Polytechnic Institute","serial_number":"0fa16da02499d58ff063ad7398b10de0"},
      {"common_name":"evil.example.com","name_value":"Some Other Org","serial_number":"bb22"},
      {"common_name":"","name_value":"SUNY Polytechnic Institute","serial_number":"cc33"}
    ]`

	got := crtshOrgCerts(body, "SUNY Polytechnic Institute")
	if len(got) != 2 {
		t.Fatalf("want 2 certs (dedup serial, drop mismatched org and empty CN), got %d: %+v", len(got), got)
	}

	byCN := map[string]string{}
	for _, c := range got {
		byCN[c.CommonName] = c.SerialNumber
	}
	if byCN["app01.sunyit.edu"] != "0fa16da02499d58ff063ad7398b10de0" {
		t.Errorf("missing/incorrect app01.sunyit.edu: %+v", byCN)
	}
	if _, ok := byCN["sunyit.edu"]; !ok {
		t.Errorf("wildcard *.sunyit.edu should reduce to sunyit.edu: %+v", byCN)
	}
	if _, ok := byCN["evil.example.com"]; ok {
		t.Error("an entry whose name_value is a different organization must be dropped")
	}
}

func TestCrtshOrgCertsEmptyOrBad(t *testing.T) {
	if got := crtshOrgCerts("[]", "SUNY Polytechnic Institute"); got != nil {
		t.Errorf("empty crt.sh response should yield nil, got %+v", got)
	}
	if got := crtshOrgCerts("not json", "x"); got != nil {
		t.Errorf("malformed response should yield nil, got %+v", got)
	}
}
