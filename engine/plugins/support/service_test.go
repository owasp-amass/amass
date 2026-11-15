// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support_test

import (
	"net/netip"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

func port(n int) *oamgen.PortRelation {
	return &oamgen.PortRelation{Name: "port", PortNumber: n, Protocol: "tcp"}
}

func web(id, server string) *oamplat.Service {
	return &oamplat.Service{ID: id, Type: "web-service", Output: "<html>", OutputLen: 6,
		Attributes: map[string][]string{"Server": {server}}}
}

// A service seen again on the same port of a name's address is the stored
// service, not a new one; a different server header is a different service.
func TestCreateServiceAssetReusesTheStoredService(t *testing.T) {
	sess := plugintest.NewSession(t)
	name := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	addr := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.10"), Type: "IPv4"})
	sess.Edge(t, name, &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}}, addr)

	first, err := support.CreateServiceAsset(sess, addr, port(443), web("svc-1", "nginx/1.24.0"), nil)
	if err != nil {
		t.Fatal(err)
	}

	again, err := support.CreateServiceAsset(sess, name, port(443), web("svc-2", "nginx/1.24.0"), nil)
	if err != nil || again.ID != first.ID {
		t.Fatalf("the same service through the name's address was stored anew: %v, %v", again, err)
	}

	other, err := support.CreateServiceAsset(sess, name, port(443), web("svc-3", "Apache/2.4.58"), nil)
	if err != nil || other.ID == first.ID {
		t.Fatalf("a different server matched the stored service: %v, %v", other, err)
	}

	// Another port is another service.
	if p, err := support.CreateServiceAsset(sess, addr, port(8443), web("svc-4", "nginx/1.24.0"), nil); err != nil ||
		p.ID == first.ID {
		t.Fatalf("a service on another port matched: %v, %v", p, err)
	}
}

// With a certificate, the stored service matches only if it presented the
// same certificate.
func TestCreateServiceAssetComparesCertificates(t *testing.T) {
	sess := plugintest.NewSession(t)
	addr := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.20"), Type: "IPv4"})
	cert := &oamcert.TLSCertificate{Version: "3", SerialNumber: "01", SubjectCommonName: "www.example.com",
		IssuerCommonName: "Example CA",
		NotBefore:        "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}
	certEnt := sess.Asset(t, cert)

	first, err := support.CreateServiceAsset(sess, addr, port(443), web("svc-1", "nginx"), cert)
	if err != nil {
		t.Fatal(err)
	}
	sess.Edge(t, first, &oamgen.SimpleRelation{Name: "certificate"}, certEnt)

	same, err := support.CreateServiceAsset(sess, addr, port(443), web("svc-2", "nginx"), cert)
	if err != nil || same.ID != first.ID {
		t.Fatalf("the same certificate did not match: %v, %v", same, err)
	}

	other := *cert
	other.SerialNumber = "02"
	diff, err := support.CreateServiceAsset(sess, addr, port(443), web("svc-3", "nginx"), &other)
	if err != nil || diff.ID == first.ID {
		t.Fatalf("another certificate matched: %v, %v", diff, err)
	}
}

// A header stored with no values must not crash the comparison.
func TestCreateServiceAssetWithEmptyHeaderValues(t *testing.T) {
	sess := plugintest.NewSession(t)
	addr := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.30"), Type: "IPv4"})

	stored := web("svc-1", "nginx")
	stored.Attributes["X-Powered-By"] = []string{}
	if _, err := support.CreateServiceAsset(sess, addr, port(80), stored, nil); err != nil {
		t.Fatal(err)
	}

	next := web("svc-2", "nginx")
	next.Attributes["X-Powered-By"] = []string{"PHP/8.3.0"}
	if _, err := support.CreateServiceAsset(sess, addr, port(80), next, nil); err != nil {
		t.Fatal(err)
	}
}
