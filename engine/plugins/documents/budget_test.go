// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// A run fetches at most the limit of documents for one registered domain,
// counted across its hosts; another domain has its own count.
func TestAdmitLimitsDocumentsPerDomain(t *testing.T) {
	f := newFixture(t, http.StatusOK, "")
	e := &et.Event{Session: f.sess}

	for i, host := range []string{"www.example.com", "docs.example.com"} {
		if why := f.d.admit(e, fmt.Sprintf("k%d", i), host, 2); why != "" {
			t.Fatalf("document %d was left: %s", i, why)
		}
	}
	if why := f.d.admit(e, "k3", "www.example.com", 2); why == "" {
		t.Error("a third document of example.com was admitted past a limit of 2")
	}
	if why := f.d.admit(e, "k4", "other.org", 2); why != "" {
		t.Errorf("another domain's document was left: %s", why)
	}
}

// A document named in a document read in this run is left for a later run;
// other documents are not.
func TestDocumentNamedInADocumentWaits(t *testing.T) {
	f := newFixture(t, http.StatusOK, "")
	e := &et.Event{Session: f.sess}

	f.d.ledFromDocument(e, "https://www.example.com/a.pdf")
	if why := f.d.admit(e, "https://www.example.com/a.pdf", "www.example.com", 100); why == "" {
		t.Error("a document named in a document was fetched in the same run")
	}
	if why := f.d.admit(e, "https://www.example.com/b.pdf", "www.example.com", 100); why != "" {
		t.Errorf("a document found another way was left: %s", why)
	}
}

// linksPDF is a PDF whose link annotations name n pages of www.example.com
// and one document there.
func linksPDF(n int) string {
	var b strings.Builder
	b.WriteString("%PDF-1.4\n1 0 obj\n<< /Producer (Acme PDF 2.1) >>\nendobj\n")
	for i := range n {
		fmt.Fprintf(&b, "%d 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://www.example.com/page%d) >> >>\nendobj\n",
			i+2, i)
	}
	fmt.Fprintf(&b, "%d 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://www.example.com/form.pdf) >> >>\nendobj\n",
		n+2)
	b.WriteString("trailer\n<< /Info 1 0 R >>\n%%EOF\n")
	return b.String()
}

// Every URL a document names is stored and linked from the File, but at most
// max_url_leads are handed to the pipeline; a document it names is not
// fetched in the same run, and is not marked, so a later run fetches it.
func TestURLLeadsAreCapped(t *testing.T) {
	links := semantics.Documents().MaxURLLeads + 10
	f := newFixture(t, http.StatusOK, linksPDF(links))
	raw := "https://www.example.com/catalog.pdf"
	if err := f.d.check(f.event(t, raw)); err != nil {
		t.Fatal(err)
	}
	fent := f.file(t, raw)
	if fent == nil {
		t.Fatal("no File stored")
	}

	var stored int
	for _, k := range neighbors(t, f, fent, "contains") {
		if strings.HasPrefix(k, "https://www.example.com/") {
			stored++
		}
	}
	if stored != links+1 {
		t.Errorf("the File links %d URLs, want all %d", stored, links+1)
	}

	var leads int
	for _, ev := range f.disp.Events() {
		if _, ok := ev.Entity.Asset.(*oamurl.URL); ok {
			leads++
		}
	}
	if want := semantics.Documents().MaxURLLeads; leads != want {
		t.Errorf("%d URL leads were handed over, want %d", leads, want)
	}

	// the cap is reached by the pages first, so hand the document over too
	doc := f.event(t, "https://www.example.com/form.pdf")
	f.d.ledFromDocument(doc, doc.Entity.Asset.Key())
	if err := f.d.check(doc); err != nil {
		t.Fatal(err)
	}
	if f.file(t, "https://www.example.com/form.pdf") != nil {
		t.Error("a document named in a document was fetched in the same run")
	}
	since, err := support.TTLStartTime(f.sess.Config(), string(oam.URL), string(oam.File), f.d.name)
	if err != nil {
		t.Fatal(err)
	}
	if f.d.attemptedSince(doc, doc.Entity, since) {
		t.Error("a document left for a later run was marked as tried")
	}
}

// When a host comes up, the documents it serves that have no File and were
// not tried recently are handed to the pipeline again; a stored document is
// not.
func TestBacklogHandsBackUnreadDocuments(t *testing.T) {
	f := newFixture(t, http.StatusOK, linksPDF(1))
	host := f.sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})

	read := "https://www.example.com/read.pdf"
	if err := f.d.check(f.event(t, read)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{read, "https://www.example.com/unread.pdf", "https://www.example.com/page.html"} {
		ev := f.event(t, raw)
		f.sess.Edge(t, ev.Entity, &oamgen.SimpleRelation{Name: "domain"}, host)
	}

	f.disp = &plugintest.Dispatcher{}
	e := &et.Event{Name: "www.example.com", Entity: host, Session: f.sess, Dispatcher: f.disp}
	if err := f.d.backlog(e); err != nil {
		t.Fatal(err)
	}

	var handed []string
	for _, ev := range f.disp.Events() {
		if u, ok := ev.Entity.Asset.(*oamurl.URL); ok {
			handed = append(handed, u.Raw)
		}
	}
	if len(handed) != 1 || handed[0] != "https://www.example.com/unread.pdf" {
		t.Errorf("handed back %v, want only the unread document", handed)
	}
}
