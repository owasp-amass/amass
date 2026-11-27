// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestInterfaceAddrs(t *testing.T) {
	if l, err := InterfaceAddrs(" "); err != nil || !l.IsZero() {
		t.Errorf("InterfaceAddrs(\"\") = %v, %v; want the zero LocalAddrs", l, err)
	}
	if l, err := InterfaceAddrs("127.0.0.1"); err != nil || l.V4 != netip.MustParseAddr("127.0.0.1") || l.V6.IsValid() {
		t.Errorf("InterfaceAddrs(127.0.0.1) = %v, %v", l, err)
	}
	// 192.0.2.0/24 is reserved for documentation, so no interface has it
	if _, err := InterfaceAddrs("192.0.2.1"); err == nil {
		t.Error("an address on no interface was accepted")
	}
	if _, err := InterfaceAddrs("no-such-iface0"); err == nil {
		t.Error("a missing interface was accepted")
	}

	ifcs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, ifc := range ifcs {
		if ifc.Flags&net.FlagLoopback != 0 {
			// a loopback interface has no global unicast address
			if l, err := InterfaceAddrs(ifc.Name); err == nil {
				t.Errorf("InterfaceAddrs(%s) = %v; want an error", ifc.Name, l)
			}
		}
	}
}

func TestLocalAddrsFor(t *testing.T) {
	v4 := LocalAddrs{V4: netip.MustParseAddr("192.0.2.1")}
	if a, ok := v4.For(netip.MustParseAddr("198.51.100.7")); !ok || a != v4.V4 {
		t.Errorf("For(IPv4) = %v, %v", a, ok)
	}
	if a, ok := v4.For(netip.MustParseAddr("::ffff:198.51.100.7")); !ok || a != v4.V4 {
		t.Errorf("For(IPv4-mapped) = %v, %v", a, ok)
	}
	if _, ok := v4.For(netip.MustParseAddr("2001:db8::7")); ok {
		t.Error("an IPv4-only interface gave an address for an IPv6 destination")
	}

	dual := LocalAddrs{V4: v4.V4, V6: netip.MustParseAddr("2001:db8::1")}
	if a, ok := dual.For(netip.MustParseAddr("2001:db8::7")); !ok || a != dual.V6 {
		t.Errorf("For(IPv6) = %v, %v", a, ok)
	}
	if got := dual.List(); len(got) != 2 || got[0] != dual.V4 {
		t.Errorf("List = %v; want IPv4 first", got)
	}
}

func TestLocalAddrsFrom(t *testing.T) {
	t.Cleanup(func() { SetLocalAddrs(LocalAddrs{}) })

	engine := LocalAddrs{V4: netip.MustParseAddr("192.0.2.1")}
	session := LocalAddrs{V6: netip.MustParseAddr("2001:db8::2")}

	if l := LocalAddrsFrom(context.Background()); !l.IsZero() {
		t.Errorf("LocalAddrsFrom = %v before any setting; want the zero LocalAddrs", l)
	}

	SetLocalAddrs(engine)
	if l := LocalAddrsFrom(context.Background()); l != engine {
		t.Errorf("LocalAddrsFrom = %v; want the engine's %v", l, engine)
	}
	if l := LocalAddrsFrom(WithLocalAddrs(context.Background(), session)); l != session {
		t.Errorf("LocalAddrsFrom = %v; want the context's %v", l, session)
	}
	if l := LocalAddrsFrom(WithLocalAddrs(context.Background(), LocalAddrs{})); l != engine {
		t.Errorf("LocalAddrsFrom = %v for a context naming none; want the engine's %v", l, engine)
	}
}

func TestNewDialContextLocalAddrs(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	dial := NewDialContext(time.Second)
	loopback := LocalAddrs{V4: netip.MustParseAddr("127.0.0.1")}

	c, err := dial(WithLocalAddrs(context.Background(), loopback), "tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial from 127.0.0.1: %v", err)
	}
	if a, ok := c.LocalAddr().(*net.TCPAddr); !ok || !a.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("the connection left from %v; want 127.0.0.1", c.LocalAddr())
	}
	_ = c.Close()

	// a name resolves, and the destination's IP version picks the address
	_, port, _ := net.SplitHostPort(l.Addr().String())
	ctx := WithLocalAddrs(context.Background(), loopback)
	if c, err := dial(ctx, "tcp", net.JoinHostPort("localhost", port)); err != nil {
		t.Errorf("dial localhost from 127.0.0.1: %v", err)
	} else {
		_ = c.Close()
	}

	// 192.0.2.0/24 is reserved for documentation, so no interface has it
	nowhere := LocalAddrs{V4: netip.MustParseAddr("192.0.2.1")}
	if c, err := dial(WithLocalAddrs(context.Background(), nowhere), "tcp", l.Addr().String()); err == nil {
		_ = c.Close()
		t.Error("a dial from an address on no interface succeeded")
	}

	v6only := LocalAddrs{V6: netip.MustParseAddr("::1")}
	if c, err := dial(WithLocalAddrs(context.Background(), v6only), "tcp", l.Addr().String()); err == nil {
		_ = c.Close()
		t.Error("an IPv6-only interface reached an IPv4 destination")
	}
}
