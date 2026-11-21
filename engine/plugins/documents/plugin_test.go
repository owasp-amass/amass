// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oampeop "github.com/owasp-amass/open-asset-model/people"
	"golang.org/x/time/rate"
)

// pdfDoc is a minimal PDF whose Info dictionary names an author, a placeholder
// last editor, the creating and producing software and a creation date.
const pdfDoc = "%PDF-1.4\n1 0 obj\n<< /Author (Jane Q. Doe) /LastModifiedBy (Microsoft Office User) " +
	"/Creator (Microsoft Word) /Producer (Acme PDF 2.1) /CreationDate (D:20240102030405Z) >>\nendobj\n" +
	"trailer\n<< /Info 1 0 R >>\n%%EOF\n"

type fixture struct {
	d    *documents
	sess *plugintest.Session
	disp *plugintest.Dispatcher
	hits *atomic.Int32

	mu    sync.Mutex
	paths []string
}

func (f *fixture) requested() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func newFixture(t *testing.T, code int, body string) *fixture {
	t.Helper()

	f := &fixture{hits: &atomic.Int32{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.mu.Unlock()
		w.WriteHeader(code)
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)

	f.sess = plugintest.NewSession(t)
	f.sess.TTL(60)
	f.sess.Scope().AddDomain("example.com")
	f.disp = &plugintest.Dispatcher{}

	f.d = NewDocuments().(*documents)
	f.d.archive = rate.NewLimiter(rate.Inf, 1)
	f.d.direct = rate.NewLimiter(rate.Inf, 1)
	f.d.ArchiveURL = srv.URL + "/web/"
	return f
}

func (f *fixture) event(t *testing.T, raw string) *et.Event {
	t.Helper()
	u := support.RawURLToOAM(raw)
	if u == nil {
		t.Fatalf("bad URL %q", raw)
	}
	ent := f.sess.Asset(t, u)
	return &et.Event{Name: raw, Entity: ent, Session: f.sess, Dispatcher: f.disp}
}

func (f *fixture) file(t *testing.T, raw string) *dbt.Entity {
	t.Helper()
	ents, err := f.sess.DB().FindEntitiesByContent(context.Background(), oam.File, time.Time{}, 0,
		dbt.ContentFilters{"url": raw})
	if err != nil || len(ents) != 1 {
		return nil
	}
	return ents[0]
}

func props(t *testing.T, f *fixture, ent *dbt.Entity) map[string]string {
	t.Helper()
	tags, err := f.sess.DB().FindEntityTags(context.Background(), ent, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, tag := range tags {
		if p, ok := tag.Property.(*oamgen.SimpleProperty); ok {
			m[p.PropertyName] = p.PropertyValue
		}
	}
	return m
}

// In passive mode the document is read from the archive's raw capture, never
// from the target, and stored as a File with its media type, size, hash
// fingerprint, metadata and the person its metadata names as author.
func TestPassiveReadsArchiveCopy(t *testing.T) {
	f := newFixture(t, http.StatusOK, pdfDoc)
	raw := "https://www.example.com/files/annual-report.pdf"
	e := f.event(t, raw)

	if err := f.d.check(e); err != nil {
		t.Fatal(err)
	}
	if paths := f.requested(); len(paths) != 1 || !strings.HasPrefix(paths[0], "/web/2id_/") {
		t.Fatalf("archive requests %v, want one raw capture", paths)
	}

	fent := f.file(t, raw)
	if fent == nil {
		t.Fatal("no File stored")
	}
	file := fent.Asset.(*oamfile.File)
	if file.Type != "application/pdf" || file.Size != int64(len(pdfDoc)) || file.Name != "annual-report.pdf" {
		t.Errorf("File %+v", file)
	}

	p := props(t, f, fent)
	if p[PropAuthor] != "Jane Q. Doe" || p[PropProducer] != "Acme PDF 2.1" || p[PropCreatorTool] != "Microsoft Word" {
		t.Errorf("metadata properties %v", p)
	}
	if !strings.Contains(p[PropRetrievedFrom], "/web/2id_/"+raw) {
		t.Errorf("retrieved from %q", p[PropRetrievedFrom])
	}

	ctx := context.Background()
	if edges, err := f.sess.DB().IncomingEdges(ctx, fent, time.Time{}, "file"); err != nil || len(edges) != 1 {
		t.Errorf("URL --file--> File edges = %v, %v", edges, err)
	}
	if edges, err := f.sess.DB().OutgoingEdges(ctx, fent, time.Time{}, "fingerprint"); err != nil || len(edges) != 1 {
		t.Errorf("fingerprint edges = %v, %v", edges, err)
	} else if id, err := f.sess.DB().FindEntityById(ctx, edges[0].ToEntity.ID); err != nil ||
		id.Asset.(*oamgen.Identifier).Type != FingerprintType {
		t.Errorf("fingerprint identifier = %v, %v", id, err)
	}

	edges, err := f.sess.DB().OutgoingEdges(ctx, fent, time.Time{}, "author")
	if err != nil || len(edges) != 1 {
		t.Fatalf("author edges = %v, %v (the placeholder last editor names no one)", edges, err)
	}
	person, err := f.sess.DB().FindEntityById(ctx, edges[0].ToEntity.ID)
	if err != nil || !strings.Contains(person.Asset.(*oampeop.Person).FullName, "Doe") {
		t.Errorf("author = %v, %v", person, err)
	}
}

// In active mode the document is fetched from its own URL. The probe client
// is pointed at the fixture server, which stands in for the target's host.
func TestActiveFetchesTheDocument(t *testing.T) {
	f := newFixture(t, http.StatusOK, pdfDoc)
	f.sess.Config().Active = true

	target := strings.TrimPrefix(strings.TrimSuffix(f.d.ArchiveURL, "/web/"), "http://")
	f.sess.Clients().Probe = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, target)
		},
	}}

	raw := "http://docs.example.com/docs/policy.pdf"
	e := f.event(t, raw)

	if err := f.d.check(e); err != nil {
		t.Fatal(err)
	}
	if paths := f.requested(); len(paths) != 1 || paths[0] != "/docs/policy.pdf" {
		t.Fatalf("requests %v, want the document's own path", paths)
	}
	if fent := f.file(t, raw); fent == nil || props(t, f, fent)[PropRetrievedFrom] != raw {
		t.Error("File not stored from the document's own URL")
	}
}

// An error page served under a document's name is not stored, and the URL is
// not asked about again within the TTL.
func TestNotADocumentIsSkipped(t *testing.T) {
	f := newFixture(t, http.StatusOK, "<html>Page not found</html>")
	raw := "https://www.example.com/files/missing.pdf"
	e := f.event(t, raw)

	for range 2 {
		if err := f.d.check(e); err != nil {
			t.Fatal(err)
		}
	}
	if f.file(t, raw) != nil {
		t.Error("an HTML page was stored as a PDF")
	}
	if f.hits.Load() != 1 {
		t.Errorf("asked %d times, want once within the TTL", f.hits.Load())
	}
}

// Out-of-scope hosts and URLs that name no document are never retrieved.
func TestOnlyInScopeDocuments(t *testing.T) {
	f := newFixture(t, http.StatusOK, pdfDoc)
	for _, raw := range []string{
		"https://cdn.other.net/files/report.pdf",
		"https://www.example.com/about/",
		"https://www.example.com/logo.png",
	} {
		if err := f.d.check(f.event(t, raw)); err != nil {
			t.Fatal(err)
		}
	}
	if f.hits.Load() != 0 {
		t.Errorf("retrieved %d times: %v", f.hits.Load(), f.requested())
	}
}

// A document longer than max_bytes is not read.
func TestFetchCapsSize(t *testing.T) {
	f := newFixture(t, http.StatusOK, strings.Repeat("x", 100))
	e := f.event(t, "https://www.example.com/a.pdf")

	if _, err := fetch(e, f.sess.Clients().General, f.d.ArchiveURL+"x", 10); err != errTooLarge {
		t.Errorf("err = %v, want errTooLarge", err)
	}
	if data, err := fetch(e, f.sess.Clients().General, f.d.ArchiveURL+"x", 100); err != nil || len(data) != 100 {
		t.Errorf("at the cap: %d bytes, %v", len(data), err)
	}
}

func TestLooksLike(t *testing.T) {
	if !looksLike("pdf", []byte("%PDF-1.7")) || looksLike("pdf", []byte("<html>")) {
		t.Error("PDF magic")
	}
	if !looksLike("ooxml", []byte("PK\x03\x04rest")) || looksLike("ooxml", []byte("%PDF-")) {
		t.Error("OOXML magic")
	}
}
