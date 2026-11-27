// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ocds

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

// withPublishers replaces the publisher catalog for the test.
func withPublishers(t *testing.T, pubs ...publisher) {
	t.Helper()

	old := loadPublishers
	loadPublishers = func() []publisher { return pubs }
	t.Cleanup(func() { loadPublishers = old })
}

func newTestOCDS(t *testing.T) (*ocds, *plugintest.Session) {
	t.Helper()

	// Bulk exports are cached under the temporary directory.
	t.Setenv("TMPDIR", t.TempDir())

	sess := plugintest.NewSession(t)
	sess.TTL(60)

	o := NewOCDS().(*ocds)
	o.rlimit = rate.NewLimiter(rate.Inf, 1)
	o.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	o.handler = &handler{name: o.name + "-Handler", plugin: o}
	return o, sess
}

func transfers(d *plugintest.Dispatcher) map[string]*oamfin.FundsTransfer {
	got := map[string]*oamfin.FundsTransfer{}
	for _, ev := range d.Events() {
		if f, ok := ev.Entity.Asset.(*oamfin.FundsTransfer); ok {
			got[f.ID] = f
		}
	}
	return got
}

func TestHandlerQueriesASupplierSearch(t *testing.T) {
	withPublishers(t,
		publisher{Key: "uk", Country: "GB", QueryURL: "https://tenders.example.gov/api/awards?supplier={supplier}", Enabled: true},
		publisher{Key: "off", Country: "GB", QueryURL: "https://off.example.gov/api?supplier={supplier}"})
	o, sess := newTestOCDS(t)
	sess.Web().Reply("GET tenders.example.gov/api/awards", http.StatusOK, `{"releases":[
	  {"ocid":"ocds-1","date":"2024-02-01","buyer":{"name":"Department for Transport"},
	   "awards":[{"id":"a1","value":{"amount":82000,"currency":"GBP"},"suppliers":[{"name":"ACME WIDGETS LTD"}]},
	             {"id":"a2","value":{"amount":5,"currency":"GBP"},"suppliers":[{"name":"Acme Gadgets Ltd"}]}]},
	  {"ocid":"ocds-2","date":"2024-03-01","parties":[{"name":"Home Office","roles":["buyer"]}],
	   "awards":[{"id":"b1","suppliers":[{"name":"Acme Widgets"}]}],
	   "contracts":[{"awardID":"b1","value":{"amount":1200,"currency":"GBP"}}]}
	]}`)

	orgent := sess.Asset(t, &oamorg.Organization{ID: "acme:test", Name: "acme widgets"})
	sess.Scope().Add(orgent.Asset)
	d := &plugintest.Dispatcher{}
	e := &et.Event{Entity: orgent, Session: sess, Dispatcher: d}
	if err := o.handler.check(e); err != nil {
		t.Fatal(err)
	}

	got := transfers(d)
	if len(got) != 2 {
		t.Fatalf("transfers = %v; requests %v", d.Names(), sess.Web().Requests())
	}
	if f := got["ocds:ocds-1:a1"]; f == nil || f.Amount != 82000 || f.Currency != "GBP" {
		t.Errorf("award a1 = %+v", f)
	}
	if f := got["ocds:ocds-2:b1"]; f == nil || f.Amount != 1200 {
		t.Errorf("award b1, valued from its contract = %+v", f)
	}

	ctx := context.Background()
	for _, ev := range d.Events() {
		if tp, err := sess.DB().OutgoingEdges(ctx, ev.Entity, time.Time{}, "third_party"); err != nil || len(tp) != 1 {
			t.Errorf("the buyer of %v = %v, %v", ev.Entity.Asset, tp, err)
		}
	}

	// The disabled publisher is never asked, and within the TTL the enabled
	// one is not asked again.
	if err := o.handler.check(e); err != nil {
		t.Fatal(err)
	}
	if reqs := sess.Web().Requests(); len(reqs) != 1 {
		t.Errorf("requests = %v", reqs)
	}
}

func TestHandlerIngestsABulkExportForItsCountry(t *testing.T) {
	withPublishers(t, publisher{Key: "mx", Country: "MX", BulkURL: "https://data.example.mx/full.jsonl.gz",
		BulkFormat: "jsonl.gz", Enabled: true})
	o, sess := newTestOCDS(t)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = io.WriteString(gz, `{"ocid":"ocds-mx-1","date":"2024-03-01","buyer":{"name":"Secretaría de Educación"},`+
		`"awards":[{"id":"a1","value":{"amount":750000,"currency":"MXN"},"suppliers":[{"name":"Gamma SA de CV"}]}]}`+"\n"+
		`{"ocid":"ocds-mx-2","awards":[{"id":"a2","value":{"amount":10,"currency":"MXN"},"suppliers":[{"name":"Unrelated Co"}]}]}`+"\n")
	_ = gz.Close()
	sess.Web().Reply("GET data.example.mx/full.jsonl.gz", http.StatusOK, buf.String())

	// An organization from elsewhere does not fetch the export.
	us := sess.Asset(t, &oamorg.Organization{ID: "us:test", Name: "gamma", Jurisdiction: "US"})
	sess.Scope().Add(us.Asset)
	if err := o.handler.check(&et.Event{Entity: us, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
		t.Fatal(err)
	}
	if reqs := sess.Web().Requests(); len(reqs) != 0 {
		t.Fatalf("a US organization fetched the MX export: %v", reqs)
	}

	mx := sess.Asset(t, &oamorg.Organization{ID: "mx:test", Name: "gamma sa de cv", Jurisdiction: "MX"})
	sess.Scope().Add(mx.Asset)
	d := &plugintest.Dispatcher{}
	if err := o.handler.check(&et.Event{Entity: mx, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}
	got := transfers(d)
	if f := got["ocds:ocds-mx-1:a1"]; len(got) != 1 || f == nil || f.Amount != 750000 || f.Currency != "MXN" {
		t.Errorf("transfers = %v; requests %v", d.Names(), sess.Web().Requests())
	}

	// A second Mexican organization reuses the downloaded export.
	other := sess.Asset(t, &oamorg.Organization{ID: "mx2:test", Name: "delta", Jurisdiction: "MX"})
	sess.Scope().Add(other.Asset)
	if err := o.handler.check(&et.Event{Entity: other, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
		t.Fatal(err)
	}
	if reqs := sess.Web().Requests(); len(reqs) != 1 {
		t.Errorf("the export was downloaded %d times: %v", len(reqs), reqs)
	}
}
