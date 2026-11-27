// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"fmt"
	"io"
	"time"
)

// WhoisQuery sends one query to a WHOIS-style server at addr (host:port) over
// TCP and returns its answer, read until the server closes the connection or
// maxBytes have arrived (0 for no limit). The context bounds the exchange; the
// connection itself is dialed within dialTimeout.
func WhoisQuery(ctx context.Context, addr, query string, dialTimeout time.Duration, maxBytes int64) (string, error) {
	conn, err := NewDialContext(dialTimeout)(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to connect to the WHOIS server %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if _, err := io.WriteString(conn, query); err != nil {
		return "", fmt.Errorf("failed to send the query to the WHOIS server %s: %w", addr, err)
	}

	var r io.Reader = conn
	if maxBytes > 0 {
		r = io.LimitReader(conn, maxBytes)
	}
	data, err := io.ReadAll(r)
	if err != nil && len(data) == 0 {
		return "", fmt.Errorf("failed to read the answer of the WHOIS server %s: %w", addr, err)
	}
	return string(data), nil
}
