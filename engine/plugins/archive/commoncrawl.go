// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

// commonCrawlIndexTTL is how long the list of crawls is reused: Common Crawl
// publishes a new crawl about once a month.
const commonCrawlIndexTTL = 24 * time.Hour

// commonCrawl asks the Common Crawl index server for the URLs its most recent
// crawl captured under a domain. The index server is keyless and often
// overloaded (503/504), so a refusal is read as no answer, never as "none".
type commonCrawl struct {
	name string
	// IndexURL lists the crawls (collinfo.json), newest first, each with the
	// CDX API endpoint of its index.
	IndexURL string
	log      *slog.Logger
	rlimit   *rate.Limiter
	// backoff are the waits before retrying a refused or failed request.
	backoff []time.Duration
	source  *et.Source

	mu    sync.Mutex
	api   string
	apiAt time.Time
}

func NewCommonCrawl() et.Plugin {
	return &commonCrawl{
		name:     "CommonCrawl",
		IndexURL: "https://index.commoncrawl.org/collinfo.json",
		rlimit:   rate.NewLimiter(rate.Every(10*time.Second), 1),
		backoff:  archiveBackoff,
		source: &et.Source{
			Name:       "CommonCrawl",
			Confidence: 80,
		},
	}
}

func (c *commonCrawl) Name() string {
	return c.name
}

func (c *commonCrawl) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       c,
		Name:         c.name + "-Handler",
		Position:     40,
		MaxInstances: 1,
		Transforms:   []string{string(oam.FQDN), string(oam.URL)},
		EventType:    oam.FQDN,
		Callback:     c.check,
	}); err != nil {
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *commonCrawl) Stop() {
	c.log.Info("Plugin stopped")
}

func (c *commonCrawl) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) || !queryRoot(e.Session, fqdn.Name) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), c.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, c.source, since) {
		return nil
	}

	api := c.latestIndex(e)
	if api == "" {
		// The crawl list could not be read; try again on a later event.
		return nil
	}

	rows, answered := c.query(e, api, fqdn.Name)
	if !answered {
		return nil
	}
	support.MarkAssetMonitored(e.Session, e.Entity, c.source)

	names, urls := harvest(e, c.source, c.name, rows)
	logAnswer(e, c.name, fqdn.Name, len(rows), len(names), len(urls))
	if len(names) > 0 {
		support.ProcessFQDNsWithSource(e, names, c.source)
	}
	if len(urls) > 0 {
		storeURLs(e, c.source, c.name, urls)
	}
	return nil
}

// latestIndex returns the CDX API endpoint of the most recent crawl, reading
// the crawl list at most once per commonCrawlIndexTTL.
func (c *commonCrawl) latestIndex(e *et.Event) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.api != "" && time.Since(c.apiAt) < commonCrawlIndexTTL {
		return c.api
	}

	body, ok := c.get(e, c.IndexURL)
	if !ok {
		e.Session.Log().Info("archive crawl list unavailable", "url", c.IndexURL,
			slog.Group("plugin", "name", c.name, "handler", c.name+"-Handler"))
		return c.api
	}

	var crawls []struct {
		ID  string `json:"id"`
		API string `json:"cdx-api"`
	}
	if err := json.Unmarshal([]byte(body), &crawls); err != nil {
		return c.api
	}
	for _, crawl := range crawls {
		if strings.HasPrefix(crawl.API, "https://") || strings.HasPrefix(crawl.API, "http://") {
			c.api, c.apiAt = crawl.API, time.Now()
			break
		}
	}

	return c.api
}

// query returns the captures the crawl's index holds under the domain, and
// whether the index answered. "No captures" (404) is an answer with none;
// a refusal or failure is no answer, so the domain is asked again later.
func (c *commonCrawl) query(e *et.Event, api, name string) ([]archiveRow, bool) {
	limit := 5 * semantics.ArchiveURLs().MaxURLsPerDomain
	q := url.Values{}
	q.Set("url", name)
	q.Set("matchType", "domain")
	q.Set("output", "json")
	q.Set("fl", "url,timestamp")
	q.Set("limit", strconv.Itoa(limit))

	body, status := c.fetch(e, api+"?"+q.Encode())
	switch {
	case status == http.StatusNotFound:
		return nil, true
	case status != http.StatusOK:
		e.Session.Log().Info("archive did not answer", "domain", name, "status", status,
			slog.Group("plugin", "name", c.name, "handler", c.name+"-Handler"))
		return nil, false
	}

	var rows []archiveRow
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var rec struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.URL == "" {
			continue
		}

		rows = append(rows, archiveRow{raw: rec.URL, timestamp: rec.Timestamp})
	}

	return rows, true
}

func (c *commonCrawl) get(e *et.Event, u string) (string, bool) {
	body, status := c.fetch(e, u)
	return body, status == http.StatusOK
}

// fetch makes one paced request and returns the body and status, or a zero
// status when the request failed.
func (c *commonCrawl) fetch(e *et.Event, u string) (string, int) {
	resp, err := request(e, c.rlimit, c.backoff, 90*time.Second, u)
	if err != nil || resp == nil {
		return "", 0
	}

	return resp.Body, resp.StatusCode
}
