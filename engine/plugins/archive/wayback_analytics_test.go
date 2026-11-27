// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// The analytics identifiers on the domain's archived homepages are stored,
// once each, as fingerprints of the homepage URL, from the pages as captured
// (id_) at each of the years asked for.
func TestWaybackArchivedAnalyticsIDs(t *testing.T) {
	var (
		mu    sync.Mutex
		asked []string
	)
	pages := []string{
		`<script>gtag('config', 'G-OLDSITE123');</script><script>(function(){hjid:1234567})</script>`,
		`<script src="https://www.googletagmanager.com/gtag/js?id=G-OLDSITE123"></script> UA-1234567-1`,
		`<html>nothing here</html>`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/web/") {
			_, _ = fmt.Fprint(w, `[["original","timestamp"]]`)
			return
		}

		mu.Lock()
		n := len(asked)
		asked = append(asked, r.URL.Path)
		mu.Unlock()
		_, _ = fmt.Fprint(w, pages[n%len(pages)])
	}))
	t.Cleanup(srv.Close)

	w, sess, _, e, _ := newWayback(t, http.StatusOK, "")
	w.URL = srv.URL + "/cdx?url="
	w.SnapshotURL = srv.URL + "/web/"
	if err := w.check(e); err != nil {
		t.Fatal(err)
	}

	if len(asked) != len(snapshotYearsAgo) {
		t.Fatalf("asked for %d archived pages, want %d: %v", len(asked), len(snapshotYearsAgo), asked)
	}
	for _, p := range asked {
		if !strings.HasSuffix(p, "id_/https://example.com/") {
			t.Errorf("archived page %s is not the homepage as captured", p)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	urls, err := sess.DB().FindEntitiesByContent(ctx, oam.URL, time.Time{}, 0,
		dbt.ContentFilters{"url": "https://example.com/"})
	if err != nil || len(urls) != 1 {
		t.Fatalf("homepage URL: %v, %v", urls, err)
	}
	if u := urls[0].Asset.(*oamurl.URL); u.Host != "example.com" {
		t.Errorf("homepage URL host %q", u.Host)
	}

	edges, err := sess.DB().OutgoingEdges(ctx, urls[0], time.Time{}, "fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, edge := range edges {
		ent, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID)
		if err != nil {
			t.Fatal(err)
		}
		if id, ok := ent.Asset.(*oamgen.Identifier); ok && id.Type == fingerprint.AnalyticsID {
			got = append(got, id.ID)
		}
	}
	slices.Sort(got)
	if want := []string{"G-OLDSITE123", "UA-1234567-1", "hotjar:1234567"}; !slices.Equal(got, want) {
		t.Errorf("stored analytics identifiers %v, want %v", got, want)
	}
}
