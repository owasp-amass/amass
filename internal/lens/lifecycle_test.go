// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestInSeries(t *testing.T) {
	cases := []struct {
		version, series string
		want            bool
	}{
		{"1.1.1k", "1.1.1", true}, {"1.1.1", "1.1.1", true}, {"2.2.34", "2.2", true},
		{"2.24.1", "2.2", false}, {"2.4.58", "2.2", false}, {"8.10", "8.1", false}, {"8.1.27", "8.1", true},
	}
	for _, c := range cases {
		if got := inSeries(c.version, c.series); got != c.want {
			t.Errorf("inSeries(%q, %q) = %v", c.version, c.series, got)
		}
	}
}

func TestUnsupportedSoftware(t *testing.T) {
	defer func(f func() time.Time) { lifecycleNow = f }(lifecycleNow)
	lifecycleNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	_ = loadSoftwareLifecycle()
	if u, ok := unsupportedRelease(IdentifiedProduct{Product: "OpenSSL", Version: "1.1.1k"}); !ok || u.Series != "1.1.1" {
		t.Errorf("OpenSSL 1.1.1k = %+v %v", u, ok)
	}
	if _, ok := unsupportedRelease(IdentifiedProduct{Product: "Apache HTTP Server", Version: "2.4.37"}); ok {
		t.Error("Apache 2.4 reported unsupported")
	}
	if _, ok := unsupportedRelease(IdentifiedProduct{Product: "PHP", Version: ""}); ok {
		t.Error("an unversioned product reported unsupported")
	}
	// A line is reported only once its end of support has passed.
	lifecycleNow = func() time.Time { return time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC) }
	if _, ok := unsupportedRelease(IdentifiedProduct{Product: "PHP", Version: "8.1.2"}); ok {
		t.Error("PHP 8.1 reported before its end of support")
	}
	lifecycleNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	// The Server header of the services fixture's web service names Apache
	// with an old OpenSSL module.
	g := graphtest.ServicesFixture()
	svc := g.Assets["svc-web"]
	content := map[string]any{}
	for k, v := range svc.Content.(map[string]any) {
		content[k] = v
	}
	content["attributes"] = map[string]any{"Server": []any{"Apache/2.4.37 (Oracle Linux Server) OpenSSL/1.1.1k PHP/7.4.33"}}
	svc.Content = content
	g.Assets["svc-web"] = svc

	r, err := FindExposure(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	var found ExposureClass
	for _, c := range r.Classes {
		if c.Name == ExposureUnsupported {
			found = c
		}
	}
	text := strings.Join(found.Examples, "\n")
	if found.Count != 2 || !strings.Contains(text, "OpenSSL 1.1.1k") || !strings.Contains(text, "PHP 7.4.33") ||
		strings.Contains(text, "Apache") {
		t.Errorf("unsupported = %+v", found)
	}
}
