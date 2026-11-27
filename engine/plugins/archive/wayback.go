// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

// wayback asks the Wayback Machine's CDX server for the URLs it captured
// under a domain.
type wayback struct {
	name string
	URL  string
	// SnapshotURL is the prefix of an archived page: a timestamp, then id_/
	// and the page's URL follow.
	SnapshotURL string
	log         *slog.Logger
	rlimit      *rate.Limiter
	// backoff are the waits before retrying a refused or failed request.
	backoff []time.Duration
	source  *et.Source
	// queue reads the archive beside the pipeline (reader).
	queue queuer
}

func NewWayback() et.Plugin {
	limit := rate.Every(10 * time.Second)

	return &wayback{
		name: "Wayback",
		// One row per distinct URL (collapse=urlkey) with the timestamp of its
		// first capture.
		URL:         "https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original,timestamp&output=json&collapse=urlkey&url=",
		SnapshotURL: "https://web.archive.org/web/",
		rlimit:      rate.NewLimiter(limit, 1),
		backoff:     archiveBackoff,
		queue:       newReader(),
		source: &et.Source{
			Name:       "Wayback",
			Confidence: 80,
		},
	}
}

func (w *wayback) Name() string {
	return w.name
}

func (w *wayback) Start(r et.Registry) error {
	w.log = r.Log().WithGroup("plugin").With("name", w.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       w,
		Name:         w.name + "-Handler",
		Position:     40,
		MaxInstances: 1,
		Transforms:   []string{string(oam.FQDN), string(oam.URL)},
		EventType:    oam.FQDN,
		Callback:     w.check,
	}); err != nil {
		return err
	}

	w.log.Info("Plugin started")
	return nil
}

func (w *wayback) Stop() {
	w.log.Info("Plugin stopped")
}

func (w *wayback) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) || !queryRoot(e.Session, fqdn.Name) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), w.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, w.source, since) {
		return nil
	}

	enqueue(w.queue, e, w.name, w.read)
	return nil
}

// read asks the archive about the domain in e, within ctx, the reader's
// budget for it.
func (w *wayback) read(ctx context.Context, e *et.Event) {
	fqdn := e.Entity.Asset.(*oamdns.FQDN)
	rows, answered := w.query(ctx, e, fqdn.Name)
	if !answered {
		// a refusal is not an answer: the domain is asked again later
		return
	}
	// a domain with more captures than are read may hold documents past
	// them: ask for its documents on their own
	if len(rows) >= 5*semantics.ArchiveURLs().MaxURLsPerDomain {
		rows = append(rows, w.documents(ctx, e, fqdn.Name)...)
	}
	support.MarkAssetMonitored(e.Session, e.Entity, w.source)

	names, urls := harvest(e, w.source, w.name, rows)
	logAnswer(e, w.name, fqdn.Name, len(rows), len(names), len(urls))
	if len(names) > 0 {
		support.ProcessFQDNsWithSource(e, names, w.source)
	}
	if len(urls) > 0 {
		storeURLs(e, w.source, w.name, urls)
	}
	// only the registered domain's homepage is read; a subdomain asked about
	// because the domain is out of scope may not be the organization's site
	if reg, err := publicsuffix.EffectiveTLDPlusOne(fqdn.Name); err == nil && reg == fqdn.Name {
		if n := w.analytics(ctx, e, fqdn.Name); n > 0 {
			e.Session.Log().Info("archived analytics identifiers stored", "domain", fqdn.Name, "count", n,
				slog.Group("plugin", "name", w.name, "handler", w.name+"-Handler"))
		}
	}
}

// waybackPageRows is how many captures one Wayback request asks for. The CDX
// server builds each answer before sending it, so a whole domain in one
// request can take minutes; smaller pages return sooner, and a slow or failed
// page costs only itself.
const waybackPageRows = 1000

// waybackPageTimeout bounds one page request; the CDX server is often slow.
const waybackPageTimeout = 3 * time.Minute

// query returns the captures the Wayback Machine holds under the domain, read
// a page at a time with the server's resume key, up to five times the URLs
// kept per domain. A refused or failed page ends the reading, and the pages
// already read are kept. answered is false when the first page was refused.
func (w *wayback) query(ctx context.Context, e *et.Event, name string) (rows []archiveRow, answered bool) {
	limit := 5 * semantics.ArchiveURLs().MaxURLsPerDomain

	var key string
	for pages := 0; len(rows) < limit && pages < limit/waybackPageRows+1; pages++ {
		page, next, ok := w.page(ctx, e, name, key)
		if pages == 0 {
			answered = ok
		}
		rows = append(rows, page...)
		if !ok || next == "" || len(page) == 0 {
			break
		}
		key = next
	}

	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, answered
}

// page asks for one page of captures, after the resume key when there is one.
// It returns the captures, the key for the next page ("" when this was the
// last) and whether the archive answered.
func (w *wayback) page(ctx context.Context, e *et.Event, name, key string) ([]archiveRow, string, bool) {
	// matchType=domain covers the name and every name below it
	u := fmt.Sprintf("%s%s&limit=%d&showResumeKey=true", w.URL, url.QueryEscape(name), waybackPageRows)
	if key != "" {
		u += "&resumeKey=" + url.QueryEscape(key)
	}
	resp, err := request(ctx, e, w.rlimit, w.backoff, waybackPageTimeout, u)
	// a refusal or rate limit is not read as an answer, but is logged so a
	// run that stores nothing can be told from one the archive refused
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		logRefusal(e, w.name, name, resp, err)
		return nil, "", false
	}

	var raw [][]string
	if err := json.Unmarshal([]byte(resp.Body), &raw); err != nil {
		logRefusal(e, w.name, name, resp, err)
		return nil, "", false
	}

	rows, next := waybackRows(raw)
	return rows, next, true
}

// documents asks for one page of the domain's captures of document types
// (PDF and Office files, semantics/documents.json), which a domain with many
// captures may hold past the pages read. A refusal gives none.
func (w *wayback) documents(ctx context.Context, e *et.Event, name string) []archiveRow {
	u := fmt.Sprintf("%s%s&limit=%d&filter=%s", w.URL, url.QueryEscape(name), waybackPageRows,
		url.QueryEscape("original:"+documentPattern()))
	resp, err := request(ctx, e, w.rlimit, w.backoff, waybackPageTimeout, u)
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		logRefusal(e, w.name, name, resp, err)
		return nil
	}

	var raw [][]string
	if err := json.Unmarshal([]byte(resp.Body), &raw); err != nil {
		logRefusal(e, w.name, name, resp, err)
		return nil
	}
	rows, _ := waybackRows(raw)
	// the header row ("original", "timestamp") is not a capture
	if len(rows) > 0 && rows[0].raw == "original" {
		rows = rows[1:]
	}
	return rows
}

// documentPattern is the CDX filter regex matching URLs of the document types
// Amass reads, with or without a query string.
func documentPattern() string {
	var exts []string
	for _, t := range semantics.Documents().Types {
		exts = append(exts, regexp.QuoteMeta(strings.TrimPrefix(t.Ext, ".")))
	}
	return `(?i).*\.(` + strings.Join(exts, "|") + `)(\?.*)?$`
}

// waybackRows reads a CDX JSON answer: the header row, then one row per
// capture (original, timestamp), then, when more remain, an empty row and a
// row holding only the resume key for the next page.
func waybackRows(raw [][]string) ([]archiveRow, string) {
	var next string
	rows := make([]archiveRow, 0, len(raw))
	for i, r := range raw {
		switch len(r) {
		case 0:
			// the empty row comes just before the resume key
			if i+1 < len(raw) && len(raw[i+1]) == 1 {
				next = raw[i+1][0]
			}
			return rows, next
		case 2:
			rows = append(rows, archiveRow{raw: r[0], timestamp: r[1]})
		}
	}
	return rows, next
}
