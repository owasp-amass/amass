// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ocds

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// Bulk-ingestion bounds.
const (
	// bulkTTL is how long a downloaded bulk export is reused before it is
	// fetched again. Bulk OCDS exports change at most daily.
	bulkTTL = 24 * time.Hour
	// bulkMaxLines bounds how many release lines one scan reads.
	bulkMaxLines = 5_000_000
	// bulkMaxLineBytes bounds one release line; OCDS compiled releases can be
	// large, but not unbounded.
	bulkMaxLineBytes = 25 * 1024 * 1024
	// bulkDownloadTimeout bounds a bulk download.
	bulkDownloadTimeout = 15 * time.Minute
)

type publisher struct {
	Key      string `json:"key"`
	Country  string `json:"country"`
	Name     string `json:"name"`
	QueryURL string `json:"query_url"`
	// BulkURL is the URL of a full OCDS export (newline-delimited compiled
	// releases, optionally gzipped) for publishers with no supplier-search
	// API; BulkFormat is "jsonl" or "jsonl.gz". When BulkURL is set the
	// publisher is ingested in bulk mode.
	BulkURL    string `json:"bulk_url"`
	BulkFormat string `json:"bulk_format"`
	Enabled    bool   `json:"enabled"`
}

// bulkApplies reports whether a publisher's bulk export should be fetched for
// an organization from the given country (ISO alpha-2). Bulk ingestion is
// on-demand: it runs only when an organization from the publisher's own country
// is seen, so an enumeration that touches no organizations from a country never
// downloads that country's export.
func bulkApplies(pub publisher, country string) bool {
	return pub.BulkURL != "" && country != "" && pub.Country != "" &&
		strings.EqualFold(country, pub.Country)
}

// orgCountry is the ISO alpha-2 country of the event's organization, inferred
// from stored evidence by the shared graph helper: its jurisdiction, then the
// country of a postal address or registrant phone on its RDAP contact record.
// Jurisdiction is frequently unpopulated for foreign entities — a company
// discovered from a regional registry (e.g. a LACNIC handle with a Mexican
// address and a +52 phone) often has no jurisdiction even though its country is
// unambiguous — so the evidence fallback lets on-demand bulk ingestion still
// recognize such an organization's country. It returns "" when unknown, in
// which case no country-gated bulk export is fetched.
func (h *handler) orgCountry(e *et.Event) string {
	g := oamrepo.New(e.Session.DB(), e.Session.Config())
	ev, ok, err := graph.OrgCountry(e.Session.Ctx(), g, e.Entity.ID)
	if err != nil || !ok {
		return ""
	}
	return ev.Country
}

var loadPublishers = sync.OnceValue(func() []publisher {
	var c struct {
		Publishers []publisher `json:"publishers"`
	}
	if err := json.Unmarshal(semantics.File("ocds_publishers.json"), &c); err != nil {
		panic("ocds_publishers.json: " + err.Error())
	}
	return c.Publishers
})

// --- OCDS schema (release and record packages) ---

type ocdsValue struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

type ocdsParty struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

type ocdsRelease struct {
	OCID  string `json:"ocid"`
	Date  string `json:"date"`
	Buyer struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"buyer"`
	Parties []ocdsParty `json:"parties"`
	Awards  []struct {
		ID        string    `json:"id"`
		Date      string    `json:"date"`
		Value     ocdsValue `json:"value"`
		Suppliers []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"suppliers"`
	} `json:"awards"`
	// Some publishers (e.g. UK Find a Tender) leave award.value empty and
	// record the amount on the contract or at the tender level instead.
	Contracts []ocdsContract `json:"contracts"`
	Tender    struct {
		Value ocdsValue `json:"value"`
	} `json:"tender"`
}

type ocdsContract struct {
	AwardID    string    `json:"awardID"`
	Value      ocdsValue `json:"value"`
	DateSigned string    `json:"dateSigned"`
}

type ocdsPackage struct {
	Releases []ocdsRelease `json:"releases"`
	Records  []struct {
		CompiledRelease ocdsRelease `json:"compiledRelease"`
	} `json:"records"`
}

// award is one supplier's award, normalized from an OCDS package.
type award struct {
	ocid, id, supplier, buyer, currency, date string
	amount                                    float64
}

// parseOCDS reads an OCDS release or record package into awards, one per
// supplier named on each award.
func parseOCDS(body []byte) ([]award, error) {
	var p ocdsPackage
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}

	releases := p.Releases
	for _, r := range p.Records {
		releases = append(releases, r.CompiledRelease)
	}

	var out []award
	for _, r := range releases {
		out = append(out, awardsFromRelease(r)...)
	}
	return out, nil
}

// awardsFromRelease returns one award per supplier named on each of a
// release's awards, with the buyer resolved from the buyer field or the
// parties' roles.
func awardsFromRelease(r ocdsRelease) []award {
	buyer := r.Buyer.Name
	if buyer == "" {
		buyer = roleName(r.Parties, "buyer")
	}
	var out []award
	for _, a := range r.Awards {
		amount, currency := a.Value.Amount, a.Value.Currency
		date := a.Date
		// Fall back to the award's contracts, then the tender value, when the
		// award itself carries no amount.
		if amount == 0 {
			if sum, cur, signed := contractsTotal(r.Contracts, a.ID); sum > 0 {
				amount, currency = sum, cur
				if date == "" {
					date = signed
				}
			} else if len(r.Awards) == 1 && r.Tender.Value.Amount > 0 {
				// The tender value belongs to the whole process, so use it
				// only when there is a single award to attribute it to.
				amount, currency = r.Tender.Value.Amount, r.Tender.Value.Currency
			}
		}
		if date == "" {
			date = r.Date
		}
		for _, s := range a.Suppliers {
			if strings.TrimSpace(s.Name) == "" {
				continue
			}
			out = append(out, award{
				ocid: r.OCID, id: a.ID, supplier: s.Name, buyer: buyer,
				amount: amount, currency: currency, date: date,
			})
		}
	}
	return out
}

// contractsTotal sums the value of the contracts belonging to one award,
// when they share a currency, and returns the first contract's signing date.
func contractsTotal(contracts []ocdsContract, awardID string) (float64, string, string) {
	var sum float64
	var currency, signed string
	for _, c := range contracts {
		if c.AwardID != awardID || c.Value.Amount <= 0 {
			continue
		}
		switch {
		case currency == "":
			currency = c.Value.Currency
		case currency != c.Value.Currency:
			continue // mixed currencies; keep the first
		}
		sum += c.Value.Amount
		if signed == "" {
			signed = c.DateSigned
		}
	}
	return sum, currency, signed
}

// releasesFromLine reads one line of a bulk OCDS export, which is either a
// compiled release object or a release/record package.
func releasesFromLine(line []byte) []ocdsRelease {
	var r ocdsRelease
	if json.Unmarshal(line, &r) == nil && (r.OCID != "" || len(r.Awards) > 0) {
		return []ocdsRelease{r}
	}
	var p ocdsPackage
	if json.Unmarshal(line, &p) == nil {
		rs := p.Releases
		for _, rec := range p.Records {
			rs = append(rs, rec.CompiledRelease)
		}
		return rs
	}
	return nil
}

// scanBulk reads newline-delimited OCDS releases from r and emits each award
// whose supplier matches. It streams, so a large export is not held in memory.
// It returns whether the line limit cut the scan short.
func scanBulk(r io.Reader, match func(supplier string) bool, emit func(award)) (bool, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256*1024), bulkMaxLineBytes)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		lines++
		if lines > bulkMaxLines {
			return true, nil
		}
		for _, rel := range releasesFromLine(line) {
			for _, a := range awardsFromRelease(rel) {
				if match(a.supplier) {
					emit(a)
				}
			}
		}
	}
	return false, sc.Err()
}

// roleName returns the name of the first party holding a role.
func roleName(parties []ocdsParty, role string) string {
	for _, p := range parties {
		for _, r := range p.Roles {
			if strings.EqualFold(r, role) {
				return p.Name
			}
		}
	}
	return ""
}

func (h *handler) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return nil
	}
	country := h.orgCountry(e)

	for _, pub := range loadPublishers() {
		if !pub.Enabled {
			continue
		}
		search := strings.Contains(pub.QueryURL, "{supplier}")
		// Bulk ingestion is on-demand: a publisher's large export is fetched
		// only when an organization from that publisher's country is seen, so a
		// run that touches no organizations from a country never downloads it.
		bulk := bulkApplies(pub, country)
		if !search && !bulk {
			continue
		}

		src := &et.Source{Name: h.plugin.source.Name + ":" + pub.Key, Confidence: h.plugin.source.Confidence}
		since, err := support.TTLStartTime(e.Session.Config(),
			string(oam.Organization), string(oam.FundsTransfer), h.plugin.name)
		if err != nil {
			return err
		}
		if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
			continue
		}
		// A supplier-search endpoint is cheaper than a full bulk scan, so
		// prefer it when the publisher offers both.
		if search {
			h.query(e, e.Entity, o.Name, pub)
		} else {
			h.queryBulk(e, e.Entity, o.Name, pub)
		}
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}
	return nil
}

func (h *handler) query(e *et.Event, orgent *dbt.Entity, name string, pub publisher) {
	u := strings.ReplaceAll(pub.QueryURL, "{supplier}", url.QueryEscape(name))

	_ = support.WaitLimit(e.Session.Ctx(), h.plugin.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 45*time.Second)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	e.Session.NetSem().Release()
	cancel()
	if err != nil || resp.StatusCode != 200 || resp.Body == "" {
		if err != nil {
			e.Session.Log().Error(fmt.Sprintf("OCDS %s query for %s failed: %s", pub.Key, name, err),
				slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		}
		return
	}

	awards, err := parseOCDS([]byte(resp.Body))
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("failed to parse OCDS %s for %s: %s", pub.Key, name, err),
			slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return
	}

	seen := map[string]bool{}
	for i := range awards {
		a := &awards[i]
		if !semantics.SameOrgName(name, a.supplier) {
			continue
		}
		id := "ocds:" + a.ocid + ":" + a.id
		if seen[id] {
			continue
		}
		seen[id] = true
		h.store(e, orgent, a, id)
	}
}

// queryBulk ingests a publisher's full OCDS export: it ensures the export is
// cached, then streams it, storing each award whose supplier is the subject.
func (h *handler) queryBulk(e *et.Event, orgent *dbt.Entity, name string, pub publisher) {
	path, err := h.plugin.ensureBulk(e, pub)
	if err != nil || path == "" {
		if err != nil {
			e.Session.Log().Error(fmt.Sprintf("OCDS %s bulk fetch failed: %s", pub.Key, err),
				slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		}
		return
	}

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	var r io.Reader = f
	if bulkGzipped(pub) {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}

	seen := map[string]bool{}
	truncated, err := scanBulk(r,
		func(supplier string) bool { return semantics.SameOrgName(name, supplier) },
		func(a award) {
			if e.Session.Ctx().Err() != nil {
				return
			}
			id := "ocds:" + a.ocid + ":" + a.id
			if seen[id] {
				return
			}
			seen[id] = true
			h.store(e, orgent, &a, id)
		})
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("OCDS %s bulk scan failed: %s", pub.Key, err),
			slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
	}
	if truncated {
		e.Session.Log().Warn(fmt.Sprintf("OCDS %s bulk scan stopped at %d lines", pub.Key, bulkMaxLines),
			slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
	}
}

// ensureBulk returns a local path to the publisher's bulk export, downloading
// it when it is missing or older than bulkTTL. The file is shared across the
// organizations of a run.
func (o *ocds) ensureBulk(e *et.Event, pub publisher) (string, error) {
	dir := filepath.Join(os.TempDir(), "amass-ocds")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	dst := filepath.Join(dir, "ocds-"+pub.Key+bulkExt(pub))
	o.bulkMu.Lock()
	defer o.bulkMu.Unlock()
	if err := support.CachedDownload(e, pub.BulkURL, dst, bulkTTL, bulkDownloadTimeout, 0); err != nil {
		return "", err
	}
	return dst, nil
}

// bulkGzipped reports whether a publisher's bulk export is gzip-compressed.
func bulkGzipped(pub publisher) bool {
	return strings.Contains(pub.BulkFormat, "gz") || strings.HasSuffix(pub.BulkURL, ".gz")
}

// bulkExt is the on-disk extension for a publisher's bulk export.
func bulkExt(pub publisher) string {
	if bulkGzipped(pub) {
		return ".jsonl.gz"
	}
	return ".jsonl"
}

func (h *handler) store(e *et.Event, orgent *dbt.Entity, a *award, id string) {
	// An award without a value (award, contract or tender) is skipped.
	if fundent := org.StoreReceivedTransfer(e, orgent, org.ReceivedTransfer{
		ID: id, Reference: a.ocid + ":" + a.id, Amount: a.amount, Currency: a.currency, Date: a.date,
		Funder: a.buyer,
	}, h.plugin.source); fundent != nil {
		org.DispatchTransfers(e, fundent)
	}
}
