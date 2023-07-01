// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"context"
	"fmt"

	"github.com/owasp-amass/amass/v3/net/http"
)

func (s *Script) getCachedResponse(ctx context.Context, url string, ttl int) (*http.Response, error) {
	return nil, fmt.Errorf("failed to obtain a cached response for %s", url)
}

func (s *Script) setCachedResponse(ctx context.Context, url string, resp *http.Response) error {
	return nil
}
