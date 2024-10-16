// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"testing"

	"github.com/owasp-amass/open-asset-model/network"
)

func TestNetblock(t *testing.T) {
	g := NewGraph("memory", "", "")
	defer g.Remove()

	t.Run("Testing UpsertNetblock...", func(t *testing.T) {
		a, err := g.UpsertNetblock(context.Background(), "10.0.0.0/8")
		if err != nil {
			t.Errorf("error inserting netblock: %v", err)
		}

		if netblock, ok := a.Asset.(*network.Netblock); !ok || netblock.CIDR.String() != "10.0.0.0/8" {
			t.Error("insert returned an invalid netblock")
		}
	})
}
