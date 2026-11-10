// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"

	jarm "github.com/caffix/jarm-go"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
)

// tlsTarget starts a local TLS server and returns it as a JARM target.
func tlsTarget(t *testing.T) (*network.IPAddress, *general.PortRelation) {
	t.Helper()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	// JARM's probes are meant to fail some handshakes; keep the server quiet.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	p, _ := strconv.Atoi(port)
	return &network.IPAddress{Address: netip.MustParseAddr(host), Type: "IPv4"},
		&general.PortRelation{Name: "port", PortNumber: p, Protocol: "TCP"}
}

func plainDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func TestJARMFingerprintsALocalTLSServer(t *testing.T) {
	ip, port := tlsTarget(t)
	first, err := jarmFingerprint(context.Background(), plainDial, ip, port)
	if err != nil || first == jarm.ZeroHash || len(first) != len(jarm.ZeroHash) {
		t.Fatalf("fingerprint = %q, %v", first, err)
	}

	second, err := jarmFingerprint(context.Background(), plainDial, ip, port)
	if err != nil || second != first {
		t.Errorf("fingerprints differ: %q and %q (%v)", first, second, err)
	}
}

func TestJARMSurvivesAFailedProbe(t *testing.T) {
	ip, port := tlsTarget(t)
	var calls atomic.Int32
	flaky := func(ctx context.Context, network, address string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("connection refused")
		}

		return plainDial(ctx, network, address)
	}

	hash, err := jarmFingerprint(context.Background(), flaky, ip, port)
	if err != nil || hash == jarm.ZeroHash {
		t.Errorf("one failed probe voided the fingerprint: %q, %v", hash, err)
	}
}

func TestJARMFailsWhenNoProbeConnects(t *testing.T) {
	ip, port := tlsTarget(t)
	refuse := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	if hash, err := jarmFingerprint(context.Background(), refuse, ip, port); err == nil {
		t.Errorf("fingerprint %q with no connection", hash)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := jarmFingerprint(ctx, plainDial, ip, port); !errors.Is(err, context.Canceled) {
		t.Errorf("a canceled session probed anyway: %v", err)
	}
}

func TestJARMRejectsUnsupportedTargets(t *testing.T) {
	if _, err := jarmFingerprint(context.Background(), plainDial, &oamdns.FQDN{Name: "example.com"},
		&general.PortRelation{PortNumber: 0}); err == nil {
		t.Error("port 0 was accepted")
	}
	if _, err := jarmFingerprint(context.Background(), plainDial, &network.Netblock{},
		&general.PortRelation{PortNumber: 443}); err == nil {
		t.Error("a target that is not a host was accepted")
	}
}
