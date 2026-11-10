// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"net/netip"
	"testing"

	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

func TestJARMTargetsTheHostNotTheService(t *testing.T) {
	name := &dbt.Entity{ID: "1", Asset: &oamdns.FQDN{Name: "www.example.com"}}
	addr := &dbt.Entity{ID: "2", Asset: &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.1"), Type: "IPv4"}}
	svc := &dbt.Entity{ID: "3", Asset: &oamplat.Service{ID: "svc", Type: "HTTP"}}
	tcp := &dbt.Edge{Relation: &oamgen.PortRelation{Name: "port", PortNumber: 443, Protocol: "TCP"}}

	for _, host := range []*dbt.Entity{name, addr} {
		if f := jarmTarget(host, tcp); f == nil || f.asset != host || f.port != tcp {
			t.Errorf("target for %s = %+v", host.Asset.Key(), f)
		}
	}
	if f := jarmTarget(name, &dbt.Edge{Relation: &oamgen.PortRelation{Name: "port", PortNumber: 443,
		Protocol: "tcp"}}); f == nil {
		t.Error("a lowercase tcp port was skipped")
	}
	if f := jarmTarget(name, &dbt.Edge{Relation: &oamgen.PortRelation{Name: "port", PortNumber: 53,
		Protocol: "UDP"}}); f != nil {
		t.Error("a UDP port was probed")
	}
	if f := jarmTarget(svc, tcp); f != nil {
		t.Error("a service was used as the host")
	}
	if f := jarmTarget(name, &dbt.Edge{Relation: &oamgen.SimpleRelation{Name: "node"}}); f != nil {
		t.Error("a relation without a port was probed")
	}
}
