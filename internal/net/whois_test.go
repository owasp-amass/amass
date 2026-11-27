// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// whoisServer answers each connection with the query it read, upper-cased,
// then closes it.
func whoisServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(conn).ReadString('\n')
			_, _ = conn.Write([]byte(strings.ToUpper(line) + "rest of the answer\n"))
			_ = conn.Close()
		}
	}()
	return ln.Addr().String()
}

func TestWhoisQuery(t *testing.T) {
	addr := whoisServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got, err := WhoisQuery(ctx, addr, "-i mnt-by EXAMPLE-MNT\r\n", time.Second, 0)
	if err != nil || got != "-I MNT-BY EXAMPLE-MNT\r\nrest of the answer\n" {
		t.Fatalf("WhoisQuery = %q, %v", got, err)
	}

	// The answer is cut at the byte limit.
	if got, err := WhoisQuery(ctx, addr, "abc\n", time.Second, 2); err != nil || got != "AB" {
		t.Errorf("limited answer = %q, %v", got, err)
	}

	// Nothing listening: an error.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	_ = ln.Close()
	if _, err := WhoisQuery(ctx, closed, "x\n", time.Second, 0); err == nil {
		t.Error("a closed port answered")
	}
}
