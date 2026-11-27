// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"fmt"
	"net/http"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"golang.org/x/time/rate"
)

// fetchTimeout bounds one FetchBody request.
const fetchTimeout = 30 * time.Second

// FetchBody GETs a URL with the session's general client, after waiting on
// lim when it is set, and returns the body of a 200 answer. maxBytes, when
// positive, rejects a larger body.
func FetchBody(e *et.Event, u string, lim *rate.Limiter, maxBytes int) ([]byte, error) {
	if lim != nil {
		_ = WaitLimit(e.Session.Ctx(), lim)
	}
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), fetchTimeout)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected answer", u)
	}
	if maxBytes > 0 && len(resp.Body) > maxBytes {
		return nil, fmt.Errorf("%s: answer larger than %d bytes", u, maxBytes)
	}
	return []byte(resp.Body), nil
}
