// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

func TestParseRecord(t *testing.T) {
	r, err := parseRecord("13335 | 1.1.1.1 | 1.1.1.0/24 | US | ARIN | 2010-07-14 | Cloudflare, Inc.\n")
	if err != nil || r.ASN != 13335 || r.Prefix != netip.MustParsePrefix("1.1.1.0/24") ||
		r.ASName != "Cloudflare, Inc." || r.AllocatedDate.Year() != 2010 {
		t.Errorf("got %+v, %v", r, err)
	}

	// a missing or odd date does not lose the AS number and prefix
	if r, err := parseRecord("64500 | 2001:db8::1 | 2001:db8::/32 | ZZ | RIPE |  | Example"); err != nil ||
		r.ASN != 64500 || !r.AllocatedDate.IsZero() {
		t.Errorf("an empty date gave %+v, %v", r, err)
	}

	// a header line before the record is skipped
	if r, err := parseRecord("AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n" +
		"15169 | 8.8.8.8 | 8.8.8.0/24 | US | ARIN | 1992-12-01 | Google LLC"); err != nil || r.ASN != 15169 {
		t.Errorf("a header line gave %+v, %v", r, err)
	}

	for _, bad := range []string{"", "Error: no match", "13335 | 1.1.1.1", "13335 | x | 1.1.1.0/24 | US | ARIN | | n"} {
		if _, err := parseRecord(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// whoisServer answers each request with the record for its address,
// counting the requests.
func whoisServer(t *testing.T, records map[string]string) (string, int, *atomic.Int32) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = ln.Close() })

	var hits atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			hits.Add(1)
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					if line := strings.TrimSpace(sc.Text()); line != "begin" && line != "end" && line != "" {
						_, _ = io.WriteString(conn, records[line]+"\n")
						return
					}
				}
			}()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, &hits
}

func newBGPTools(t *testing.T, host string, port int) *bgpTools {
	t.Helper()

	bt := NewBGPTools().(*bgpTools)
	bt.addr, bt.port = host, port
	bt.rlimit = rate.NewLimiter(rate.Inf, 1)
	bt.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	bt.netblock = &netblock{name: bt.name + "-IP-Handler", plugin: bt}
	return bt
}

// An address's netblock and autonomous system are stored, linked and
// dispatched; another address in the same netblock and a later session
// within the TTL do not ask bgp.tools again.
func TestNetblockForAddress(t *testing.T) {
	host, port, hits := whoisServer(t, map[string]string{
		"1.1.1.1": "13335 | 1.1.1.1 | 1.1.1.0/24 | US | ARIN | 2010-07-14 | Cloudflare, Inc.",
	})
	bt := newBGPTools(t, host, port)

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	disp := &plugintest.Dispatcher{}
	ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("1.1.1.1"), Type: "IPv4"})
	if err := bt.netblock.check(&et.Event{Entity: ip, Session: sess, Dispatcher: disp}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(disp.Names(), ","); got != "1.1.1.0/24,AS13335" {
		t.Errorf("dispatched %s", got)
	}
	if found, _ := sess.CIDRanger().Contains(net.ParseIP("1.1.1.200")); !found {
		t.Error("the netblock was not added to the session's ranges")
	}

	other := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("1.1.1.2"), Type: "IPv4"})
	if err := bt.netblock.check(&et.Event{Entity: other, Session: sess, Dispatcher: disp}); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Errorf("bgp.tools was asked %d times, want once", hits.Load())
	}
}

// Reserved addresses are never sent to bgp.tools.
func TestNetblockSkipsReservedAddresses(t *testing.T) {
	host, port, hits := whoisServer(t, nil)
	bt := newBGPTools(t, host, port)

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	for _, a := range []string{"10.1.2.3", "192.168.0.1", "127.0.0.1"} {
		ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr(a), Type: "IPv4"})
		if err := bt.netblock.check(&et.Event{
			Entity:     ip,
			Session:    sess,
			Dispatcher: &plugintest.Dispatcher{},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("bgp.tools was asked %d times about reserved addresses", hits.Load())
	}
}

// The plugin starts without resolving bgp.tools, and a failed lookup is
// not repeated within a minute.
func TestServerAddrRetry(t *testing.T) {
	bt := NewBGPTools().(*bgpTools)
	bt.retry = time.Now().Add(time.Minute)

	if _, err := bt.serverAddr(t.Context()); err == nil || !strings.Contains(err.Error(), "not known yet") {
		t.Errorf("a lookup within a minute of a failure gave %v", err)
	}

	bt.addr = "192.0.2.1"
	if got, err := bt.serverAddr(t.Context()); got != "192.0.2.1" || err != nil {
		t.Errorf("a known address gave %q, %v", got, err)
	}
}
