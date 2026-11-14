// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/platform"
)

// TestPortRelationsReadAsPort stores a port relation the way the HTTP
// probes do (named tcp_port_443) and reads it back as OAM's "port".
func TestPortRelationsReadAsPort(t *testing.T) {
	ctx := context.Background()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "ports.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()
	name, err := db.CreateAsset(ctx, &oamdns.FQDN{Name: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	svc, err := db.CreateAsset(ctx, &platform.Service{ID: "svc-443", Type: "web-service"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateEdge(ctx, &dbt.Edge{FromEntity: name, ToEntity: svc,
		Relation: &general.PortRelation{Name: "tcp_port_443", PortNumber: 443, Protocol: "TCP"}}); err != nil {
		t.Fatal(err)
	}

	adapter := Adapter{Repo: db}
	for _, label := range []string{"", "port"} {
		edges, _, err := adapter.EdgesLimited(ctx, name.ID, "out", label, time.Time{}, 10)
		if err != nil || len(edges) != 1 || edges[0].Label != "port" || edges[0].Type != "PortRelation" {
			t.Errorf("bounded read with label %q = %+v, %v", label, edges, err)
		}
	}

	edges, err := adapter.Edges(ctx, name.ID, "out", "port", time.Time{})
	if err != nil || len(edges) != 1 || edges[0].Label != "port" {
		t.Errorf("read with label port = %+v, %v", edges, err)
	}
	if _, ok := (Catalog{}).Meaning("FQDN", edges[0].Label, edges[0].Type, "Service"); !ok {
		t.Error("the semantics table has no meaning for the port relation as read")
	}
}
