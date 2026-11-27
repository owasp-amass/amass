// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// unbatched offers every reader a lens uses except the batch reads.
type unbatched struct{ a Adapter }

func (u unbatched) GetAsset(ctx context.Context, id string) (graph.Asset, error) {
	return u.a.GetAsset(ctx, id)
}

func (u unbatched) FindAssets(ctx context.Context, t string, since time.Time, limit int) ([]graph.Asset, error) {
	return u.a.FindAssets(ctx, t, since, limit)
}

func (u unbatched) Edges(ctx context.Context, id, dir, label string, since time.Time) ([]graph.Relation, error) {
	return u.a.Edges(ctx, id, dir, label, since)
}

func (u unbatched) Evidence(ctx context.Context, id string, limit int) ([]graph.Evidence, error) {
	return u.a.Evidence(ctx, id, limit)
}

func (u unbatched) EdgesLimited(ctx context.Context, id, dir, label string, since time.Time, limit int) ([]graph.Relation, bool, error) {
	return u.a.EdgesLimited(ctx, id, dir, label, since, limit)
}

func (u unbatched) EdgesPage(ctx context.Context, id, dir, label string, since time.Time, cursor string, limit int) ([]graph.Relation, string, error) {
	return u.a.EdgesPage(ctx, id, dir, label, since, cursor, limit)
}

func (u unbatched) EdgeEvidence(ctx context.Context, id string, limit int) ([]graph.Evidence, error) {
	return u.a.EdgeEvidence(ctx, id, limit)
}

// TestLensSameWithBatchReads walks a footprint whose root has more edges
// than one read returns, with and without the batch reads: the lens finds
// the same services in fewer reads.
func TestLensSameWithBatchReads(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "batch-walk.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = repo.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rootEnt, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: "walk.example"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < graph.MaxEdgeRead+20; i++ {
		child, err := repo.CreateAsset(ctx, &oamdns.FQDN{Name: fmt.Sprintf("h%03d.walk.example", i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: rootEnt, ToEntity: child,
			Relation: &oamgen.SimpleRelation{Name: "node"}}); err != nil {
			t.Fatal(err)
		}
		if i%100 != 0 {
			continue
		}

		ip, err := repo.CreateAsset(ctx, &oamnet.IPAddress{Address: netip.AddrFrom4([4]byte{192, 0, 2, byte(i / 100)}),
			Type: "IPv4"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: child, ToEntity: ip, Relation: &oamdns.BasicDNSRelation{
			Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}}}); err != nil {
			t.Fatal(err)
		}

		svc, err := repo.CreateAsset(ctx, &oamplat.Service{ID: fmt.Sprintf("svc-%d", i), Type: "HTTP",
			Output: "ok", Attributes: map[string][]string{"Server": {"nginx/1.25.3"}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: child, ToEntity: svc,
			Relation: &oamgen.PortRelation{Name: "tcp_port_443", PortNumber: 443, Protocol: "TCP"}}); err != nil {
			t.Fatal(err)
		}
	}

	batched := Adapter{Repo: repo, Stats: &ReadStats{}}
	root, err := batched.GetAsset(ctx, rootEnt.ID)
	if err != nil {
		t.Fatal(err)
	}

	limits := lens.LensLimits{MaxAssets: 5000}
	with, err := lens.FindServices(ctx, batched, Catalog{}, root, limits)
	if err != nil {
		t.Fatal(err)
	}

	without, err := lens.FindServices(ctx, unbatched{a: Adapter{Repo: repo}}, Catalog{}, root, limits)
	if err != nil {
		t.Fatal(err)
	}

	if stripReads(with) != stripReads(without) {
		t.Fatalf("the lens differs with batch reads:\n%s\n---\n%s", lens.FormatServicesReport(with),
			lens.FormatServicesReport(without))
	}

	t.Logf("lens reads: %d with batch reads, %d without; adapter calls %v", with.Reads, without.Reads,
		batched.Stats.calls)
	if len(with.Services) != 6 {
		t.Errorf("found %d services, want 6", len(with.Services))
	}
	if with.Reads > without.Reads {
		t.Errorf("batch reads made more lens reads: %d > %d", with.Reads, without.Reads)
	}
	if batched.Stats.calls["GetAssets"] == 0 || batched.Stats.calls["EdgesPerLabel"] == 0 {
		t.Errorf("the batch reads were not used: %v", batched.Stats.calls)
	}
	if n := batched.Stats.calls["GetAsset"]; n > 10 {
		t.Errorf("%d single asset reads remain", n)
	}

	// A footprint cut short by the asset limit samples the same assets.
	small := lens.LensLimits{MaxAssets: 40}
	with, err = lens.FindServices(ctx, batched, Catalog{}, root, small)
	if err != nil {
		t.Fatal(err)
	}

	without, err = lens.FindServices(ctx, unbatched{a: Adapter{Repo: repo}}, Catalog{}, root, small)
	if err != nil {
		t.Fatal(err)
	}
	if !with.Truncated || stripReads(with) != stripReads(without) {
		t.Fatalf("the limited lens differs with batch reads:\n%s\n---\n%s", lens.FormatServicesReport(with),
			lens.FormatServicesReport(without))
	}
}

// stripReads is a report's services without its read count.
func stripReads(r lens.ServicesReport) string {
	r.Reads = 0
	return lens.FormatServicesReport(r)
}
