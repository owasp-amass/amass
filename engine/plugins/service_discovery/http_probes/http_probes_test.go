// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

const page = `<html><head><title>Example Portal</title></head><body>hello</body></html>`

// favicon is the icon the test server serves at /favicon.ico; the probe hashes
// these bytes in Shodan's convention and stores the hash as a fingerprint.
var favicon = []byte("\x00\x00\x01\x00amass-test-favicon-bytes")

func newProbing(t *testing.T) (*httpProbing, *plugintest.Session) {
	t.Helper()

	hp := NewHTTPProbing().(*httpProbing)
	hp.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	hp.fqdnend = &fqdnEndpoint{name: hp.name + "-FQDN-Interrogation", plugin: hp}
	hp.ipaddr = &ipaddrEndpoint{name: hp.name + "-IPAddress-Interrogation", plugin: hp}

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	return hp, sess
}

func serve(t *testing.T, tls bool) *httptest.Server {
	t.Helper()

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(favicon)
			return
		}
		w.Header().Set("Server", "nginx/1.25.3")
		_, _ = fmt.Fprint(w, page)
	})

	if !tls {
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		return srv
	}

	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &cryptotls.Config{Certificates: []cryptotls.Certificate{selfSigned(t, "www.example.com")}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// selfSigned returns a certificate for name, with the subject and issuer
// common names that stored certificates have.
func selfSigned(t *testing.T, name string) cryptotls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return cryptotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fingerprints returns the id_type -> id of every fingerprint Identifier
// linked from ent by a "fingerprint" edge.
func fingerprints(t *testing.T, sess *plugintest.Session, ent *dbt.Entity) map[string]string {
	t.Helper()

	edges, err := sess.DB().OutgoingEdges(sess.Ctx(), ent, time.Time{}, "fingerprint")
	if err != nil {
		t.Fatal(err)
	}

	out := map[string]string{}
	for _, edge := range edges {
		id, err := sess.DB().FindEntityById(sess.Ctx(), edge.ToEntity.ID)
		if err != nil || id == nil {
			continue
		}
		if ident, ok := id.Asset.(*oamgen.Identifier); ok {
			out[ident.Type] = ident.ID
		}
	}

	return out
}

// A probed web page becomes a web service on the probed port, with the
// page's response and fingerprints.
func TestProbeStoresTheService(t *testing.T) {
	hp, sess := newProbing(t)
	srv := serve(t, false)

	host := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	findings := hp.query(&et.Event{Entity: host, Session: sess}, host, srv.URL, 8080)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want the service", len(findings))
	}

	svc, ok := findings[0].To.Asset.(*oamplat.Service)
	if !ok || svc.Type != "web-service" || svc.Output != page {
		t.Fatalf("got %+v", findings[0].To.Asset)
	}
	if rel, ok := findings[0].Rel.(*oamgen.PortRelation); !ok || rel.PortNumber != 8080 || rel.Protocol != "TCP" {
		t.Errorf("the relation is %+v", findings[0].Rel)
	}
	fps := fingerprints(t, sess, findings[0].To)
	if fps[fingerprint.Title] != "Example Portal" {
		t.Errorf("the title fingerprint is %q", fps[fingerprint.Title])
	}
	if got, want := fps[fingerprint.FaviconMMH3], fingerprint.FaviconHash(favicon); got != want {
		t.Errorf("the favicon fingerprint is %q, want %q", got, want)
	}
}

// A TLS service's certificate is stored and linked to the service.
func TestProbeStoresTheCertificate(t *testing.T) {
	hp, sess := newProbing(t)
	srv := serve(t, true)
	sess.Clients().Probe = srv.Client()

	host := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	findings := hp.query(&et.Event{Entity: host, Session: sess}, host, srv.URL, 443)

	var cert *oamcert.TLSCertificate
	for _, f := range findings {
		if c, ok := f.To.Asset.(*oamcert.TLSCertificate); ok {
			cert = c
			if _, ok := f.From.Asset.(*oamplat.Service); !ok {
				t.Errorf("the certificate is linked from %T", f.From.Asset)
			}
		}
	}
	if cert == nil || cert.SerialNumber != "4242" || cert.SubjectCommonName != "www.example.com" {
		t.Errorf("no certificate was stored; findings %v", findings)
	}
}

// A page that cannot be reached stores nothing.
func TestProbeUnreachable(t *testing.T) {
	hp, sess := newProbing(t)
	srv := serve(t, false)
	url := srv.URL
	srv.Close()

	host := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	if findings := hp.query(&et.Event{Entity: host, Session: sess}, host, url, 80); len(findings) != 0 {
		t.Errorf("an unreachable page gave %d findings", len(findings))
	}
}

// Probing is active collection: nothing is probed in a passive enumeration.
// Where probes may reach is the gate's (registry gate_test.go).
func TestProbingNeedsActive(t *testing.T) {
	hp, sess := newProbing(t)
	ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.1"), Type: "IPv4"})
	disp := &plugintest.Dispatcher{}

	sess.Config().Active = false
	if err := hp.ipaddr.check(&et.Event{Entity: ip, Session: sess, Dispatcher: disp}); err != nil {
		t.Fatal(err)
	}
	if len(disp.Events()) != 0 {
		t.Errorf("dispatched %v", disp.Names())
	}
}

// Within the TTL, only the services this plugin found are returned again.
func TestLookupOnlyThisPluginsServices(t *testing.T) {
	hp, sess := newProbing(t)

	host := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	mine := sess.Asset(t, &oamplat.Service{ID: "mine", Type: "web-service"})
	theirs := sess.Asset(t, &oamplat.Service{ID: "theirs", Type: "ssh"})

	edge := sess.Edge(t, host, &oamgen.PortRelation{Name: "tcp_port_443", PortNumber: 443, Protocol: "TCP"}, mine)
	if _, err := sess.DB().CreateEdgeProperty(sess.Ctx(), edge,
		&oamgen.SourceProperty{Source: hp.source.Name, Confidence: 100}); err != nil {
		t.Fatal(err)
	}

	other := sess.Edge(t, host, &oamgen.PortRelation{Name: "tcp_port_22", PortNumber: 22, Protocol: "TCP"}, theirs)
	if _, err := sess.DB().CreateEdgeProperty(sess.Ctx(), other,
		&oamgen.SourceProperty{Source: "Banner-Probes", Confidence: 100}); err != nil {
		t.Fatal(err)
	}

	findings := hp.fqdnend.lookup(&et.Event{Entity: host, Session: sess}, host, time.Now().Add(-time.Hour))
	if len(findings) != 1 || findings[0].To.ID != mine.ID {
		var got []string
		for _, f := range findings {
			got = append(got, f.To.Asset.Key())
		}

		t.Errorf("the lookup gave %v, want only mine", got)
	}
}

// A certificate that names its subject only in its alternative names, as
// httptest's does, is stored too.
func TestProbeStoresACertificateWithoutCommonNames(t *testing.T) {
	hp, sess := newProbing(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, page)
	}))
	t.Cleanup(srv.Close)
	sess.Clients().Probe = srv.Client()

	cert := srv.Certificate()
	if cert.Subject.CommonName != "" || cert.Issuer.CommonName != "" {
		t.Skip("httptest's certificate now has common names")
	}

	host := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	var stored *oamcert.TLSCertificate
	for _, f := range hp.query(&et.Event{Entity: host, Session: sess}, host, srv.URL, 443) {
		if c, ok := f.To.Asset.(*oamcert.TLSCertificate); ok {
			stored = c
		}
	}
	if stored == nil || stored.SerialNumber != cert.SerialNumber.String() || stored.SubjectCommonName != "" {
		t.Errorf("the certificate stored is %+v", stored)
	}
}
