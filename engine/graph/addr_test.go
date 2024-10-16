// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/network"
)

func TestAddress(t *testing.T) {
	g := NewGraph("memory", "", "")
	defer g.Remove()

	t.Run("Testing UpsertAddress...", func(t *testing.T) {
		want := "192.168.1.1"

		if got, err := g.UpsertAddress(context.Background(), want); err != nil {
			t.Errorf("error inserting address:%v\n", err)
		} else if a, ok := got.Asset.(*network.IPAddress); !ok || a.Address.String() != want {
			t.Error("IP address was not returned properly")
		}
	})

	t.Run("Testing UpsertA...", func(t *testing.T) {
		_, err := g.UpsertA(context.Background(), "owasp.org", "192.168.1.1")
		if err != nil {
			t.Errorf("error inserting fqdn: %v", err)
		}
	})

	t.Run("Testing UpsertAAAA...", func(t *testing.T) {
		_, err := g.UpsertAAAA(context.Background(), "owasp.org", "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
		if err != nil {
			t.Errorf("error inserting AAAA record: %v", err)
		}
	})
}

func TestNameToAddrs(t *testing.T) {
	fqdn := "caffix.net"
	addr1 := "192.168.1.1"
	addr2 := "192.168.1.2"
	cname := "www.caffix.net"
	ctarget := "www.utica.edu"
	caddr := "72.237.4.113"
	srv := "_sip._tcp.caffix.net"
	srvtarget := "sip.caffix.net"
	srvaddr := "192.168.2.1"

	g := NewGraph("memory", "", "")
	defer g.Remove()

	if _, err := g.NamesToAddrs(context.Background(), time.Time{}, fqdn); err == nil {
		t.Errorf("did not return an error when provided parameters not existing in the graph")
	}

	expected := stringset.New()
	defer expected.Close()

	src, err := g.DB.Create(nil, "", &domain.FQDN{Name: fqdn})
	if err != nil {
		t.Errorf("Failed to create the source asset %s: %v", fqdn, err)
		return
	}
	if _, err := g.DB.Create(src, "a_record", &network.IPAddress{Address: netip.MustParseAddr(addr1), Type: "IPv4"}); err != nil {
		t.Errorf("Failed to create the %s relation to %s: %v", fqdn, addr1, err)
		return
	}
	expected.Insert(fqdn + "|" + addr1)
	if _, err := g.DB.Create(src, "a_record", &network.IPAddress{Address: netip.MustParseAddr(addr2), Type: "IPv4"}); err != nil {
		t.Errorf("Failed to create the %s relation to %s: %v", fqdn, addr2, err)
		return
	}
	expected.Insert(fqdn + "|" + addr2)
	src, err = g.DB.Create(nil, "", &domain.FQDN{Name: cname})
	if err != nil {
		t.Errorf("Failed to create the source asset %s: %v", cname, err)
		return
	}
	src, err = g.DB.Create(src, "cname_record", &domain.FQDN{Name: ctarget})
	if err != nil {
		t.Errorf("Failed to create the %s relation to %s: %v", cname, ctarget, err)
		return
	}
	if _, err := g.DB.Create(src, "a_record", &network.IPAddress{Address: netip.MustParseAddr(caddr), Type: "IPv4"}); err != nil {
		t.Errorf("Failed to create the %s relation to %s: %v", ctarget, caddr, err)
		return
	}
	expected.InsertMany(cname+"|"+caddr, ctarget+"|"+caddr)
	src, err = g.DB.Create(nil, "", &domain.FQDN{Name: srv})
	if err != nil {
		t.Errorf("Failed to create the source asset %s: %v", srv, err)
		return
	}
	src, err = g.DB.Create(src, "srv_record", &domain.FQDN{Name: srvtarget})
	if err != nil {
		t.Errorf("Failed to create the %s relation to %s: %v", srv, srvtarget, err)
		return
	}
	if _, err := g.DB.Create(src, "a_record", &network.IPAddress{Address: netip.MustParseAddr(srvaddr), Type: "IPv4"}); err != nil {
		t.Errorf("Failed to create the %s relation to %s: %v", srvtarget, srvaddr, err)
		return
	}
	expected.InsertMany(srv+"|"+srvaddr, srvtarget+"|"+srvaddr)

	// test case where cnames and srvs are populated
	pairs, err := g.NamesToAddrs(context.Background(), time.Time{}, fqdn, cname, ctarget, srv, srvtarget)
	if err != nil {
		t.Errorf("failed to obtain the name / address pairs: %v", err)
		return
	}
	// remove the name / address pairs returned from the list of expected values
	for _, pair := range pairs {
		expected.Remove(pair.FQDN.Name + "|" + pair.Addr.Address.String())
	}
	// check for name / address pairs that were expected and were not returned
	for _, e := range expected.Slice() {
		if pair := strings.Split(e, "|"); len(pair) == 2 {
			t.Errorf("Failed to return the %s / %s pair", pair[0], pair[1])
		}
	}

	// check that no results are provided when entered before the since parameter
	if pairs, err := g.NamesToAddrs(context.Background(), time.Now(), fqdn, cname, ctarget, srv, srvtarget); err == nil && len(pairs) > 0 {
		t.Errorf("failed to filter results using the provided since parameter")
	}
}
