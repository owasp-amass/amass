// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNetUsageCounts(t *testing.T) {
	u := &NetUsage{}
	ctx := WithNetUsage(context.Background(), u)
	if NetUsageFrom(ctx) != u {
		t.Fatal("the context does not carry the counters")
	}
	if NetUsageFrom(context.Background()) != nil {
		t.Fatal("a context without counters returned some")
	}

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 25 {
				NetUsageFrom(ctx).DNSQuery(DNSAnswered, time.Millisecond)
				NetUsageFrom(ctx).DNSQuery(DNSNoRecord, time.Millisecond)
				NetUsageFrom(ctx).DNSQuery(DNSFailed, time.Millisecond)
				NetUsageFrom(ctx).Waited("api.(*crtsh).query", 2*time.Millisecond)
			}
		}()
	}

	wg.Wait()
	d := u.DNS()
	if d.Queries != 300 || d.Answered != 100 || d.NoRecord != 100 || d.Failed != 100 || d.Took != 300*time.Millisecond {
		t.Errorf("DNS counts %+v", d)
	}
	if w := u.Waits()["api.(*crtsh).query"]; w.Waits != 100 || w.Took != 200*time.Millisecond {
		t.Errorf("rate limit waits %+v", w)
	}
}

// Code without a session's context counts nothing and does not fail.
func TestNetUsageNil(t *testing.T) {
	var u *NetUsage
	u.DNSQuery(DNSAnswered, time.Second)
	u.Waited("x", time.Second)
	u.Log(slog.Default(), "nothing")
	if u.DNS().Queries != 0 || len(u.Waits()) != 0 {
		t.Error("a nil NetUsage counted")
	}
}

func TestNetUsageBoundsSources(t *testing.T) {
	u := &NetUsage{maxWaits: 3}
	for i := range 10 {
		u.Waited(fmt.Sprintf("source-%d", i), time.Millisecond)
	}

	w := u.Waits()
	if len(w) != 4 || w["other"].Waits != 7 {
		t.Errorf("waits %+v, want 3 sources and the rest under other", w)
	}
}

func TestNetUsageLog(t *testing.T) {
	u := &NetUsage{}
	u.DNSQuery(DNSAnswered, 4*time.Millisecond)
	u.DNSQuery(DNSFailed, 2*time.Millisecond)
	u.Waited("scrape.(*bing).query", time.Second)
	u.Waited("api.(*crtsh).query", 3*time.Second)

	var b bytes.Buffer
	u.Log(slog.New(slog.NewTextHandler(&b, nil)), "shared network use")
	out := b.String()
	for _, want := range []string{"dns_queries=2", "dns_answered=1", "dns_failed=1", "dns_mean=3ms",
		"source=api.(*crtsh).query"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "crtsh") > strings.Index(out, "bing") {
		t.Errorf("the longest wait is not listed first:\n%s", out)
	}
}
