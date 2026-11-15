// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"runtime"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"golang.org/x/time/rate"
)

// WaitLimit waits for a data source's rate limit, as lim.Wait does, and
// counts the wait for the session whose context ctx is, under the plugin
// function that waited, so the sessions' shares of each source can be
// compared.
func WaitLimit(ctx context.Context, lim *rate.Limiter) error {
	start := time.Now()
	err := lim.Wait(ctx)
	et.NetUsageFrom(ctx).Waited(limitCaller(), time.Since(start))
	return err
}

// limitCaller names the plugin function that waited: the first caller
// outside this package under engine/plugins, such as
// "api.(*securityTrails).query".
func limitCaller() string {
	pcs := make([]uintptr, 16)
	n := runtime.Callers(3, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if i := strings.Index(f.Function, "/engine/plugins/"); i >= 0 &&
			!strings.Contains(f.Function, "/engine/plugins/support.") {
			return f.Function[i+len("/engine/plugins/"):]
		}
		if !more {
			return "unknown"
		}
	}
}
