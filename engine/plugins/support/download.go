// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

// CachedDownload keeps a local copy of a large file at dst, downloading it
// again when the copy is missing or older than ttl. It streams through the
// session's bulk client (the general client when there is none), writing to
// a temporary file first so a failed or oversized download never replaces a
// good copy. maxBytes, when positive, rejects a larger file. It returns an
// error when no copy could be had; a failed refresh of an existing copy is
// reported but the old copy stays usable.
func CachedDownload(e *et.Event, u, dst string, ttl, timeout time.Duration, maxBytes int64) error {
	if fi, err := os.Stat(dst); err == nil && time.Since(fi.ModTime()) < ttl {
		return nil
	}

	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	client := e.Session.Clients().Bulk
	if client == nil {
		client = e.Session.Clients().General
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %s", u, resp.Status)
	}
	if maxBytes > 0 && resp.ContentLength > maxBytes {
		return fmt.Errorf("%s: %d bytes is over the %d byte limit", u, resp.ContentLength, maxBytes)
	}

	body := io.Reader(resp.Body)
	if maxBytes > 0 {
		body = io.LimitReader(resp.Body, maxBytes+1)
	}
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && maxBytes > 0 && n > maxBytes {
		err = fmt.Errorf("%s: over the %d byte limit", u, maxBytes)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
