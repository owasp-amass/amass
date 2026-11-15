// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Update limits. NVD allows 5 requests in 30 seconds without an API key
// and 50 with one (https://nvd.nist.gov/developers/start-here), and a
// change window of at most 120 days.
const (
	nvdPageSize      = 2000
	nvdKeylessPause  = 6500 * time.Millisecond
	nvdKeyedPause    = 700 * time.Millisecond
	nvdMaxChangeDays = 120
	maxResponseBytes = 256 << 20
)

// Updater refreshes a data file.
type Updater struct {
	Client *http.Client
	// APIKey is an NVD API key, which allows faster requests; optional.
	APIKey string
	Now    func() time.Time
	// Log, when set, reports each product fetched.
	Log func(format string, args ...any)
	// Pause overrides the time between NVD requests; zero keeps NVD's
	// published rate limit.
	Pause time.Duration
	pause time.Duration
	last  time.Time
}

// UpdateResult summarizes a refresh.
type UpdateResult struct {
	Products int `json:"products"`
	Full     int `json:"full"`
	Changed  int `json:"changed"`
	CVEs     int `json:"cves"`
	KEV      int `json:"kev"`
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}

	return time.Now()
}

func (u *Updater) logf(format string, args ...any) {
	if u.Log != nil {
		u.Log(format, args...)
	}
}

// Update refreshes the data at path for every product in the catalog: a
// product never fetched, or not fetched within NVD's change window, is
// fetched in full; the others only for what changed since. The KEV catalog
// is read in full. The file is written when everything succeeded.
func (u *Updater) Update(ctx context.Context, path string) (UpdateResult, error) {
	var res UpdateResult
	cat, err := LoadCatalog()
	if err != nil {
		return res, err
	}

	d, err := Load(path)
	if err != nil {
		return res, err
	}
	if u.Client == nil {
		u.Client = &http.Client{Timeout: 2 * time.Minute}
	}
	switch {
	case u.Pause > 0:
		u.pause = u.Pause
	case u.APIKey != "":
		u.pause = nvdKeyedPause
	default:
		u.pause = nvdKeylessPause
	}

	for _, cpe := range cat.cpes() {
		started := u.now().UTC()
		p := d.Products[cpe]
		full := p == nil || started.Sub(p.FetchedAt) > nvdMaxChangeDays*24*time.Hour
		var since time.Time
		if full {
			p = &ProductData{CVEs: map[string]*CVE{}}
			res.Full++
		} else {
			since = p.FetchedAt.Add(-time.Hour)
		}

		n, err := u.fetchProduct(ctx, cat.NVDAPI, cpe, since, started, p)
		if err != nil {
			return res, fmt.Errorf("%s: %w", cpe, err)
		}

		u.logf("%s: %d CVEs (%d changed)", cpe, len(p.CVEs), n)

		p.FetchedAt = started
		d.Products[cpe] = p
		res.Products++
		res.Changed += n
		res.CVEs += len(p.CVEs)
	}

	kev, err := u.fetchKEV(ctx, cat.KEVFeed)
	if err != nil {
		return res, fmt.Errorf("KEV catalog: %w", err)
	}

	d.KEV, d.KEVFetchedAt = kev, u.now().UTC()
	res.KEV = len(kev)

	d.About, d.CatalogHash, d.UpdatedAt = dataAbout, cat.hash(), u.now().UTC()
	return res, d.Save(path)
}

// Stale reports whether the data at path needs a refresh: older than
// maxAge, or fetched for a different set of catalog products.
func Stale(path string, maxAge time.Duration, now time.Time) bool {
	d, err := Load(path)
	if err != nil || d.UpdatedAt.IsZero() {
		return true
	}

	cat, err := LoadCatalog()
	if err != nil {
		return false
	}

	return d.CatalogHash != cat.hash() || now.Sub(d.UpdatedAt) > maxAge
}

// nvdMetric is one CVSS score of a CVE.
type nvdMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// nvdConfig is one of a CVE's configurations: the products it affects.
type nvdConfig struct {
	Nodes []struct {
		CPEMatch []struct {
			Vulnerable            bool   `json:"vulnerable"`
			Criteria              string `json:"criteria"`
			VersionStartIncluding string `json:"versionStartIncluding"`
			VersionStartExcluding string `json:"versionStartExcluding"`
			VersionEndIncluding   string `json:"versionEndIncluding"`
			VersionEndExcluding   string `json:"versionEndExcluding"`
		} `json:"cpeMatch"`
	} `json:"nodes"`
}

// nvdResponse is the part of an NVD CVE API 2.0 response the updater reads.
type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID             string                 `json:"id"`
			Published      string                 `json:"published"`
			Metrics        map[string][]nvdMetric `json:"metrics"`
			Configurations []nvdConfig            `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// fetchProduct reads the CVEs naming cpe, all of them or those modified
// between since and until, into p, and returns how many it read.
func (u *Updater) fetchProduct(ctx context.Context, api, cpe string, since, until time.Time, p *ProductData) (int,
	error) {
	var windows [][2]time.Time
	if since.IsZero() {
		windows = [][2]time.Time{{}}
	} else {
		for start := since; start.Before(until); start = start.Add(nvdMaxChangeDays * 24 * time.Hour) {
			end := start.Add(nvdMaxChangeDays * 24 * time.Hour)
			if end.After(until) {
				end = until
			}

			windows = append(windows, [2]time.Time{start, end})
		}
	}

	read := 0
	for _, w := range windows {
		for start := 0; ; {
			q := url.Values{}
			q.Set("virtualMatchString", cpe)
			q.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
			q.Set("startIndex", strconv.Itoa(start))
			if !w[0].IsZero() {
				q.Set("lastModStartDate", w[0].UTC().Format("2006-01-02T15:04:05.000"))
				q.Set("lastModEndDate", w[1].UTC().Format("2006-01-02T15:04:05.000"))
			}

			var page nvdResponse
			if err := u.getJSON(ctx, api+"?"+q.Encode(), true, &page); err != nil {
				return read, err
			}
			for _, v := range page.Vulnerabilities {
				c := cveOf(cpe, v.CVE.ID, v.CVE.Published, v.CVE.Metrics, v.CVE.Configurations)
				if len(c.Ranges) == 0 {
					delete(p.CVEs, c.ID) // no longer names the product as vulnerable
				} else {
					p.CVEs[c.ID] = c
				}

				read++
			}

			start += len(page.Vulnerabilities)
			if len(page.Vulnerabilities) == 0 || start >= page.TotalResults {
				break
			}
		}
	}

	return read, nil
}

// cveOf keeps a CVE's score and the version ranges of its vulnerable
// configurations that name cpe.
func cveOf(cpe, id, published string, metrics map[string][]nvdMetric, configs []nvdConfig) *CVE {
	c := &CVE{ID: id}
	if t, err := time.Parse("2006-01-02T15:04:05.000", published); err == nil {
		c.Published = t
	}

	// The newest CVSS version NVD scored, preferring its own (Primary) score.
	for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		ms := metrics[key]
		for i, m := range ms {
			if m.Type == "Primary" || i == len(ms)-1 {
				c.Score, c.Severity = m.CVSSData.BaseScore, m.CVSSData.BaseSeverity
				if c.Severity == "" {
					c.Severity = m.BaseSeverity
				}

				break
			}
		}
		if c.Score > 0 {
			break
		}
	}

	prefix := cpe + ":"
	for _, conf := range configs {
		for _, n := range conf.Nodes {
			for _, m := range n.CPEMatch {
				if !m.Vulnerable || !strings.HasPrefix(m.Criteria, prefix) {
					continue
				}

				r := Range{StartIncl: m.VersionStartIncluding, StartExcl: m.VersionStartExcluding,
					EndIncl: m.VersionEndIncluding, EndExcl: m.VersionEndExcluding}
				if f := strings.Split(m.Criteria, ":"); len(f) > 6 && f[5] != "*" && f[5] != "-" {
					r.Version = f[5]
					if f[6] != "*" && f[6] != "-" {
						r.Version += f[6] // 8.9 with update p1 is 8.9p1
					}
				} else if len(f) > 5 && f[5] == "-" {
					continue // "-" names no version
				}

				c.Ranges = append(c.Ranges, r)
			}
		}
	}

	return c
}

// kevResponse is the part of CISA's KEV catalog the updater reads.
type kevResponse struct {
	Vulnerabilities []struct {
		CVEID             string `json:"cveID"`
		VulnerabilityName string `json:"vulnerabilityName"`
		DateAdded         string `json:"dateAdded"`
		DueDate           string `json:"dueDate"`
	} `json:"vulnerabilities"`
}

func (u *Updater) fetchKEV(ctx context.Context, feed string) (map[string]KEVEntry, error) {
	var k kevResponse
	if err := u.getJSON(ctx, feed, false, &k); err != nil {
		return nil, err
	}
	if len(k.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("the catalog lists no vulnerabilities")
	}

	out := make(map[string]KEVEntry, len(k.Vulnerabilities))
	for _, v := range k.Vulnerabilities {
		out[v.CVEID] = KEVEntry{Name: v.VulnerabilityName, DateAdded: v.DateAdded, DueDate: v.DueDate}
	}

	return out, nil
}

// getJSON fetches and decodes a URL; NVD requests are spaced to its rate
// limit and send the API key.
func (u *Updater) getJSON(ctx context.Context, rawURL string, nvd bool, v any) error {
	if nvd {
		if wait := u.pause - time.Since(u.last); !u.last.IsZero() && wait > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		u.last = time.Now()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "OWASP Amass vulnerability updater")
	if nvd && u.APIKey != "" {
		req.Header.Set("apiKey", u.APIKey)
	}

	resp, err := u.Client.Do(req)
	if err != nil {
		return err
	}

	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s %s", req.URL.Host, resp.Status, strings.TrimSpace(string(msg)))
	}

	return json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(v)
}
