// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamfile "github.com/owasp-amass/open-asset-model/file"
)

// runStore keeps the properties written to any File.
type runStore struct {
	props map[string]oam.Property
	next  int
}

func (s *runStore) FindEntityById(_ context.Context, id string) (*dbt.Entity, error) {
	return &dbt.Entity{ID: id, Asset: &oamfile.File{URL: id}}, nil
}

func (s *runStore) CreateEntityProperty(_ context.Context, _ *dbt.Entity, p oam.Property) (*dbt.EntityTag, error) {
	s.next++
	id := fmt.Sprintf("t%d", s.next)
	s.props[id] = p
	return &dbt.EntityTag{ID: id, Property: p}, nil
}

func (s *runStore) DeleteEntityTag(_ context.Context, id string) error {
	if _, ok := s.props[id]; !ok {
		return errors.New("not found")
	}
	delete(s.props, id)
	return nil
}

// textFetcher serves each document's text and version from memory, recording
// what was fetched.
type textFetcher struct {
	texts   map[string]string
	fetched []string
}

func (f *textFetcher) Document(_ context.Context, src lens.DocumentSource) (string, string, error) {
	f.fetched = append(f.fetched, src.URL)
	text, ok := f.texts[src.URL]
	if !ok {
		return "", "", errors.New("fetch: status 404 Not Found")
	}
	return text, "sha-" + src.URL[strings.LastIndex(src.URL, "/")+1:], nil
}

// documentFixture stores Files a, b and c on owasp.org, each with the
// content hash of its stored version; b's version predates versions being
// recorded and already has statements.
func documentFixture() graphtest.VendorGraph {
	g := graphtest.VendorFixture()
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	for _, f := range []string{"a", "b", "c"} {
		url := "https://www.owasp.org/" + f + ".pdf"
		g.Assets["u-"+f] = graph.Asset{ID: "u-" + f, Type: "URL", Key: url, Content: map[string]any{"url": url}}
		g.Assets["f-"+f] = graph.Asset{ID: "f-" + f, Type: "File", Key: url,
			Content: map[string]any{"url": url, "type": "application/pdf"}}
		g.Links = append(g.Links,
			graph.Relation{ID: "u-" + f + "-domain", FromID: "u-" + f, ToID: "www.owasp.org", Label: "domain",
				Type: "SimpleRelation"},
			graph.Relation{ID: "u-" + f + "-file", FromID: "u-" + f, ToID: "f-" + f, Label: "file",
				Type: "SimpleRelation"})
		if f != "b" {
			g.Assets["h-"+f] = graph.Asset{ID: "h-" + f, Type: "Identifier", Key: "file_sha256:sha-" + f + ".pdf",
				Content: map[string]any{"id": "sha-" + f + ".pdf", "id_type": "file_sha256"}}
			g.Links = append(g.Links, graph.Relation{ID: "f-" + f + "-fp", FromID: "f-" + f, ToID: "h-" + f,
				Label: "fingerprint", Type: "SimpleRelation"})
		}
	}
	g.EvidenceByID["f-b"] = []graph.Evidence{graphtest.SimpleProp(review.PropDocStatement, `{"predicate":"unit_of"}`)}
	return g
}

const runReply = `{"category": "staff_directory", "assets": [
  {"type": "FQDN", "value": "vpn.sunyit.edu", "quote": "Staff connect remotely through vpn.sunyit.edu"}],
 "statements": [
  {"subject": "SUNY Poly Foundation", "subject_type": "Organization", "predicate": "unit_of",
   "object": "SUNY Polytechnic Institute", "object_type": "Organization",
   "quote": "The SUNY Poly Foundation is a division of SUNY Polytechnic Institute."},
  {"subject": "Acme", "subject_type": "Organization", "predicate": "supplied_by",
   "object": "SUNY Polytechnic Institute", "object_type": "Organization",
   "quote": "Acme supplies the College"}],
 "attributes": []}`

// A run fetches each document and reads all of its text, up to its limit,
// stores what passes validation with the version read, and reads each version
// once: a version already read is skipped without fetching it.
func TestReadDocuments(t *testing.T) {
	g := documentFixture()
	fetcher := &textFetcher{texts: map[string]string{
		"https://www.owasp.org/a.pdf": docText, "https://www.owasp.org/b.pdf": docText,
		"https://www.owasp.org/c.pdf": docText}}
	store := &runStore{props: map[string]oam.Property{}}
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	opts := DocumentRunOptions{Model: &docModel{replies: []string{runReply}}, ModelID: "test-model", Max: 1,
		Fetcher: fetcher, Schema: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}}

	// a dry run stores nothing
	dry := opts
	dry.DryRun = true
	run, err := ReadDocuments(context.Background(), g, store, j, g.Assets["owasp.org"], dry)
	if err != nil {
		t.Fatal(err)
	}
	if run.Read != 1 || len(store.props) != 0 || len(run.Documents) != 1 || len(run.Documents[0].Stored) != 3 {
		t.Fatalf("dry run %+v, stored %d", run, len(store.props))
	}

	run, err = ReadDocuments(context.Background(), g, store, j, g.Assets["owasp.org"], opts)
	if err != nil {
		t.Fatal(err)
	}
	if run.Read != 1 || run.Skipped != 1 || run.Remaining != 1 || run.Statements != 3 || run.Rejected != 1 {
		t.Fatalf("run %+v", run)
	}
	d := run.Documents[0]
	if d.URL != "https://www.owasp.org/a.pdf" || d.Category != "staff_directory" || d.ReadingID == "" ||
		d.SHA256 != "sha-a.pdf" {
		t.Fatalf("document %+v", d)
	}
	if len(store.props) != 3 {
		t.Fatalf("stored %d properties, want the category, the asset and one relation", len(store.props))
	}

	// a's version is read: the next run fetches only c
	fetcher.fetched = nil
	opts.Max = 0
	run, err = ReadDocuments(context.Background(), g, store, j, g.Assets["owasp.org"], opts)
	if err != nil {
		t.Fatal(err)
	}
	if run.Read != 1 || run.Skipped != 2 || len(fetcher.fetched) != 1 || fetcher.fetched[0] != "https://www.owasp.org/c.pdf" {
		t.Fatalf("second run %+v, fetched %v", run, fetcher.fetched)
	}

	// a document that cannot be fetched fails without stopping the run
	delete(fetcher.texts, "https://www.owasp.org/a.pdf")
	opts.Reread = true
	run, err = ReadDocuments(context.Background(), g, store, j, g.Assets["owasp.org"], opts)
	if err != nil || run.Failed != 1 || run.Read != 2 || run.Failures[FailureFetch] != 1 {
		t.Fatalf("reread %+v, %v", run, err)
	}
	for _, d := range run.Documents {
		if d.URL == "https://www.owasp.org/a.pdf" && d.Failure != FailureFetch {
			t.Errorf("failed document %+v, want failure %q", d, FailureFetch)
		}
	}

	// a File the caller skips is neither fetched nor counted
	fetcher.fetched = nil
	opts.Skip = func(id string) bool { return id == "f-a" }
	run, err = ReadDocuments(context.Background(), g, store, j, g.Assets["owasp.org"], opts)
	if err != nil || run.Failed != 0 || run.Remaining != 0 {
		t.Fatalf("run skipping a %+v, %v", run, err)
	}
	for _, u := range fetcher.fetched {
		if u == "https://www.owasp.org/a.pdf" {
			t.Fatal("a skipped File was fetched")
		}
	}
	opts.Skip = nil

	if _, err := ReadDocuments(context.Background(), g, store, j, g.Assets["owasp.org"],
		DocumentRunOptions{}); err == nil {
		t.Fatal("a run without a document model read documents")
	}
}

// Each failure says why: a custom fetcher's error is a failed fetch, an
// oversized download is too large, and a model request that ran out of time
// is told from one that failed otherwise. Only the failures that may pass are
// retried.
func TestFailureKinds(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errors.New("status 404 Not Found"), FailureFetch},
		{&documentError{kind: FailureUnsupported, err: errors.New("x")}, FailureUnsupported},
		{fmt.Errorf("wrapped: %w", &documentError{kind: FailureExtract, err: errors.New("x")}), FailureExtract},
		{&documentError{kind: modelFailure(fmt.Errorf("post: %w", context.DeadlineExceeded)), err: errors.New("x")},
			FailureModelTimeout},
		{&documentError{kind: modelFailure(errors.New("status 500")), err: errors.New("x")}, FailureModel},
	} {
		if got := failureKind(tc.err); got != tc.want {
			t.Errorf("failureKind(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	if !errors.As(fmt.Errorf("fetch: %w", tooLargeError{max: 10}), new(tooLargeError)) {
		t.Error("an oversized download is not recognized")
	}
	for kind, want := range map[string]bool{FailureFetch: true, FailureModel: true, FailureModelTimeout: true,
		FailureUnsupported: false, FailureTooLarge: false, FailureExtract: false} {
		if retryable(kind) != want {
			t.Errorf("retryable(%q) = %v", kind, !want)
		}
	}
}
