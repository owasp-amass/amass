// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// DocumentSources tells the document model where each stored File the
// subject publishes can be fetched again (the archive copy the engine read,
// when it read one), the content hash of the version stored, and how many
// statements it already has.
func TestDocumentSources(t *testing.T) {
	g := graphtest.VendorFixture()
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	asset := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	for _, d := range []struct{ url, file string }{
		{"https://www.owasp.org/it/plan.pdf", "f-plan"},
		{"https://www.owasp.org/old.docx", "f-old"},
	} {
		asset("u-"+d.file, "URL", d.url, map[string]any{"url": d.url})
		link("u-"+d.file, "domain", "www.owasp.org")
		asset(d.file, "File", d.url, map[string]any{"url": d.url, "type": "application/pdf"})
		link("u-"+d.file, "file", d.file)
	}
	asset("h-plan", "Identifier", "file_sha256:abc", map[string]any{"id": "abc", "id_type": "file_sha256"})
	link("f-plan", "fingerprint", "h-plan")
	archived := "https://web.archive.org/web/2id_/https://www.owasp.org/it/plan.pdf"
	g.EvidenceByID["f-plan"] = []graph.Evidence{
		graphtest.SimpleProp(propDocRetrievedFrom, archived),
		graphtest.SimpleProp(propDocStatement, `{"kind":"asset","subject":"vpn.owasp.org"}`),
	}

	docs, err := DocumentSources(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 {
		t.Fatalf("documents %+v", docs)
	}
	plan, old := docs[0], docs[1]
	if plan.FileID != "f-plan" || plan.RetrievedFrom != archived || plan.SHA256 != "abc" || plan.Statements != 1 ||
		plan.MediaType != "application/pdf" {
		t.Fatalf("plan %+v", plan)
	}
	if old.FileID != "f-old" || old.RetrievedFrom != "" || old.SHA256 != "" || old.Statements != 0 {
		t.Fatalf("old %+v", old)
	}
}
