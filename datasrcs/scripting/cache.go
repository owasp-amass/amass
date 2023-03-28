// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v3/net/http"
)

func (s *Script) getCachedResponse(ctx context.Context, url string, ttl int) (*http.Response, error) {
	for _, db := range s.sys.GraphDatabases() {
		tCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if data, err := db.GetSourceData(tCtx, s.String(), url, ttl); err == nil {
			resp := &http.Response{}
			b := bytes.Buffer{}
			b.Write([]byte(data))

			d := gob.NewDecoder(&b)
			if err := d.Decode(&resp); err == nil {
				return resp, err
			}
		}
	}
	return nil, fmt.Errorf("failed to obtain a cached response for %s", url)
}

func (s *Script) setCachedResponse(ctx context.Context, url string, resp *http.Response) error {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	if err := e.Encode(resp); err != nil {
		return err
	}

	for _, db := range s.sys.GraphDatabases() {
		tCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if err := db.CacheSourceData(tCtx, s.String(), url, b.String()); err != nil {
			return err
		}
	}
	return nil
}
