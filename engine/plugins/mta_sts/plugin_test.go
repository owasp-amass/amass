// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mtasts

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

func TestParseSTSPolicy(t *testing.T) {
	enforce := "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.mail.example.com\r\nmax_age: 604800\r\n"
	p := ParseSTSPolicy(enforce)
	if p == nil || p.Mode != "enforce" || p.MaxAge != "604800" || len(p.MX) != 2 {
		t.Fatalf("enforce policy = %+v", p)
	}

	if p := ParseSTSPolicy("version: STSv1\nmode: testing\n"); p == nil || p.Mode != "testing" {
		t.Errorf("testing policy = %+v", p)
	}
	// Not a valid STSv1 policy, or missing a mode: no policy.
	if p := ParseSTSPolicy("mode: enforce\n"); p != nil {
		t.Errorf("a policy with no version was parsed: %+v", p)
	}
	if p := ParseSTSPolicy("version: STSv1\nmax_age: 86400\n"); p != nil {
		t.Errorf("a policy with no mode was parsed: %+v", p)
	}
}

func TestStore(t *testing.T) {
	sess := plugintest.NewSession(t)
	m := NewMTASTS().(*mtaSTS)
	e := &et.Event{Session: sess, Dispatcher: &plugintest.Dispatcher{}}

	s := m.store(e, "example.com", &STSPolicy{Mode: "testing", MaxAge: "604800", MX: []string{"mail.example.com"}})
	if s == nil {
		t.Fatal("the policy was not stored")
	}

	svc, ok := s.Asset.(*oamplat.Service)
	if !ok || svc.Type != "web-service" {
		t.Fatalf("stored asset %+v", s.Asset)
	}

	// The mode (and the other fields) are recorded as service properties.
	ctx := context.Background()
	tags, err := sess.DB().FindEntityTags(ctx, s, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, tag := range tags {
		if p, ok := tag.Property.(*oamgen.SimpleProperty); ok {
			got[p.PropertyName] = p.PropertyValue
		}
	}
	if got["mta_sts_mode"] != "testing" || got["mta_sts_max_age"] != "604800" || got["mta_sts_mx"] != "mail.example.com" {
		t.Errorf("service properties = %v", got)
	}
}
