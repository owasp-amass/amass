// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

// irrServer answers an inverse maintainer query with RPSL route objects and
// keeps the queries it was sent.
func irrServer(t *testing.T, answer string) (string, func() []string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var queries []string
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(conn).ReadString('\n')
			mu.Lock()
			queries = append(queries, strings.TrimSpace(line))
			mu.Unlock()
			_, _ = io.WriteString(conn, answer)
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), queries...)
	}
}

func linkedTo(t *testing.T, sess *plugintest.Session, from *dbt.Entity, label string) []*dbt.Entity {
	t.Helper()

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, from, time.Time{}, label)
	if err != nil {
		return nil
	}
	var out []*dbt.Entity
	for _, edge := range edges {
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func TestCheckRecordsTheRoutingRecords(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Scope().AddCIDR("192.0.2.0/24")

	sess.Web().Reply("GET stat.ripe.net/data/whois/data.json", http.StatusOK, statWhois)
	sess.Web().Reply("GET stat.ripe.net/data/rpki-validation/data.json", http.StatusOK, `{"data": {
	  "validating_roas": [{"origin": "64500", "prefix": "192.0.2.0/23", "max_length": 24, "validity": "valid"}],
	  "status": "valid"}}`)
	addr, queries := irrServer(t, "route:      192.0.2.0/24\norigin:     AS64500\nmnt-by:     MAINT-ACME\nsource:     RIPE\n\n"+
		"route:      203.0.113.0/24\norigin:     AS64501\nmnt-by:     MAINT-ACME\nsource:     RIPE\n\n"+
		"route:      198.18.0.0/15\norigin:     AS64502\nmnt-by:     MAINT-ACME\nsource:     RADB\n")

	r := NewRoutingRecords().(*routingRecords)
	r.rlimit = rate.NewLimiter(rate.Inf, 1)
	r.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	r.catalog = semantics.RoutingRegistryCatalog()
	r.catalog.IRRWhois = addr

	nb := sess.Asset(t, &oamnet.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})
	as := sess.Asset(t, &oamnet.AutonomousSystem{Number: 64500})
	sess.Edge(t, as, &general.SimpleRelation{Name: "announces"}, nb)

	e := &et.Event{Entity: nb, Session: sess, Dispatcher: &plugintest.Dispatcher{}}
	if err := r.check(e); err != nil {
		t.Fatal(err)
	}

	// The operator's maintainer, not the registry's or the upstream's.
	mnts := linkedTo(t, sess, nb, "irr_maintainer")
	if len(mnts) != 1 || mnts[0].Asset.(*general.Identifier).ID != "RIPE:MAINT-ACME" {
		t.Fatalf("maintainers = %v; requests %v", mnts, sess.Web().Requests())
	}
	if q := queries(); len(q) != 1 || q[0] != "-s RIPE -i mnt-by MAINT-ACME" {
		t.Errorf("registry queries = %v", q)
	}

	// The maintainer's other RIPE route is linked to it with its origin; the
	// RADB route is another registry's.
	ctx := context.Background()
	edges, err := sess.DB().IncomingEdges(ctx, mnts[0], time.Time{}, "irr_maintainer")
	if err != nil || len(edges) != 2 {
		t.Errorf("netblocks kept by the maintainer = %v, %v", edges, err)
	}
	other := sess.Asset(t, &oamnet.Netblock{CIDR: netip.MustParsePrefix("203.0.113.0/24"), Type: "IPv4"})
	if origins := linkedTo(t, sess, other, "irr_origin"); len(origins) != 1 ||
		origins[0].Asset.(*oamnet.AutonomousSystem).Number != 64501 {
		t.Errorf("the other route's origin = %v", origins)
	}

	// RPKI: the announced origin is valid and authorized.
	if origins := linkedTo(t, sess, nb, "rpki_origin"); len(origins) != 1 ||
		origins[0].Asset.(*oamnet.AutonomousSystem).Number != 64500 {
		t.Errorf("RPKI origins = %v", origins)
	}

	// Within the TTL nothing is asked again.
	sent := len(sess.Web().Requests())
	if err := r.check(e); err != nil {
		t.Fatal(err)
	}
	if len(sess.Web().Requests()) != sent || len(queries()) != 1 {
		t.Error("the routing records were asked for again within the TTL")
	}
}
