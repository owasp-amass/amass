// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

func TestNameKindModel(t *testing.T) {
	q := &et.NameKindQuestion{Name: "OWASP Foundation", Label: "author", RecordType: "File", Source: "Documents",
		Evidence: []string{"no person's name parsed: the parser found no given name", "the File's title is \"Annual Report\""}}

	for _, tc := range []struct {
		reply, kind string
		conf        int
		wantErr     bool
	}{
		{`{"kind":"organization","confidence":0.95,"reason":"universities are organizations","cites":[1,1]}`,
			et.NameKindOrganization, 95, false},
		{`{"kind":"unclear","confidence":0.5,"reason":"not enough","cites":[]}`, et.NameKindUnclear, 50, false},
		{`{"kind":"person","confidence":0.9,"reason":"a guess","cites":[]}`, "", 0, true},
		{`{"kind":"person","confidence":0.9,"reason":"a guess","cites":[3]}`, "", 0, true},
		{`{"kind":"role","confidence":0.9,"reason":"x","cites":[1]}`, "", 0, true},
		{`not json`, "", 0, true},
	} {
		m := &replyModel{reply: tc.reply}
		a, err := (&NameKindModel{Model: m, ModelID: "test"}).Decide(context.Background(), q)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%s: err %v", tc.reply, err)
		}
		if err == nil && (a.Kind != tc.kind || a.Confidence != tc.conf) {
			t.Errorf("%s: answer %+v", tc.reply, a)
		}
		if tc.kind == et.NameKindOrganization && len(a.Cites) != 1 {
			t.Errorf("repeated cites were kept: %v", a.Cites)
		}
		// an unreadable reply is asked again, after the question
		if len(m.asked) < 2 || !strings.Contains(m.asked[1].Text, "2. the File's title") ||
			!strings.Contains(m.asked[1].Text, "in its author field") {
			t.Errorf("the question asked:\n%v", m.asked)
		}
	}
}
