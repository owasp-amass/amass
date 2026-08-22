// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DefaultActiveResolver is the DNS server that active-derived DNS lookups
// are sent to over the active-egress dialer. The active egress is typically
// a TCP-only proxy (HTTP CONNECT or SOCKS5/tcp), so we explicitly use
// TCP DNS to a well-known authoritative-friendly resolver.
//
// Operators who need to point active DNS at their own resolver can set
// ActiveProxy to a SOCKS5 endpoint that egresses out of their network and
// the dialed resolver will be reached through there.
const DefaultActiveResolver = "1.1.1.1:53"

// ActiveDNSExchange sends a single DNS query over the supplied active-egress
// dial context. It only supports TCP DNS because the active egress is
// typically a TCP-only proxy (HTTP CONNECT or SOCKS5/tcp).
//
// Returns ErrNoActiveEgress when dial is nil; callers MUST treat the error
// as a hard failure and not fall back to direct DNS.
func ActiveDNSExchange(ctx context.Context, dial DialContext, server string, msg *dns.Msg) (*dns.Msg, error) {
	if dial == nil {
		return nil, ErrNoActiveEgress
	}
	if server == "" {
		server = DefaultActiveResolver
	}
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}

	conn, err := dial(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("active dns dial to %s failed: %w", server, err)
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(10 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	buf, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("active dns: pack failed: %w", err)
	}
	if len(buf) > 0xffff {
		return nil, errors.New("active dns: message too large for TCP")
	}

	// RFC 1035 §4.2.2: TCP DNS uses a 2-byte length prefix.
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(len(buf)))
	if _, err := conn.Write(append(hdr, buf...)); err != nil {
		return nil, fmt.Errorf("active dns: write failed: %w", err)
	}

	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("active dns: read length failed: %w", err)
	}
	rlen := binary.BigEndian.Uint16(hdr)
	rbuf := make([]byte, rlen)
	if _, err := io.ReadFull(conn, rbuf); err != nil {
		return nil, fmt.Errorf("active dns: read body failed: %w", err)
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(rbuf); err != nil {
		return nil, fmt.Errorf("active dns: unpack failed: %w", err)
	}
	return resp, nil
}
