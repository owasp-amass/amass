// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/open-asset-model/domain"
)

func TestFQDN(t *testing.T) {
	g := NewGraph("memory", "", "")
	defer g.Remove()

	name := "owasp.org"
	ctx := context.Background()
	service := "testservice.com"
	t.Run("Testing UpsertFQDN...", func(t *testing.T) {
		if a, err := g.UpsertFQDN(ctx, name); err != nil {
			t.Errorf("failed inserting FQDN: %v", err)
		} else if fqdn, ok := a.Asset.(*domain.FQDN); !ok || fqdn.Name != name {
			t.Error("error expecting FQDN")
		}
	})

	t.Run("Testing UpsertCNAME...", func(t *testing.T) {
		if _, err := g.UpsertCNAME(ctx, name, name); err != nil {
			t.Errorf("failed inserting CNAME: %v", err)
		}
	})

	t.Run("Testing IsCNAMENode...", func(t *testing.T) {
		if !g.IsCNAMENode(ctx, name, time.Time{}) {
			t.Error("failed to obtain CNAME from node")
		}
	})

	t.Run("Testing UpsertPTR...", func(t *testing.T) {
		if _, err := g.UpsertPTR(ctx, name, name); err != nil {
			t.Errorf("failed to InsertPTR: %v", err)
		}
	})

	t.Run("Testing IsPTRNode...", func(t *testing.T) {
		if !g.IsPTRNode(ctx, name, time.Time{}) {
			t.Errorf("failed to find PTRNode: %s", name)
		}
	})

	t.Run("Testing UpsertSRV...", func(t *testing.T) {
		if _, err := g.UpsertSRV(ctx, service, name); err != nil {
			t.Errorf("failed inserting service into database: %v", err)
		}
	})

	t.Run("Testing UpsertNS...", func(t *testing.T) {
		if _, err := g.UpsertNS(ctx, name, name); err != nil {
			t.Errorf("failed inserting NS record: %v", err)
		}
	})

	t.Run("Testing IsNSNode...", func(t *testing.T) {
		if !g.IsNSNode(ctx, name, time.Time{}) {
			t.Error("failed to locate NS node")
		}
	})

	t.Run("Testing UpsertMX...", func(t *testing.T) {
		if _, err := g.UpsertMX(ctx, name, name); err != nil {
			t.Errorf("failure to insert MX record: %v", err)
		}
	})

	t.Run("Testing IsMXNode...", func(t *testing.T) {
		if !g.IsMXNode(ctx, name, time.Time{}) {
			t.Errorf("failed to locate MX node")
		}
	})
}
