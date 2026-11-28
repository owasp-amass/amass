// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/coord"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// DocumentRootGraph resolves a domain name or an organization name to a
// stored asset.
type DocumentRootGraph interface {
	graph.AssetResolver
	graph.OrgSearchGraph
}

// DocumentRoot resolves the domain or organization whose documents are read.
func DocumentRoot(ctx context.Context, g DocumentRootGraph, domain, org string) (graph.Asset, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	org = strings.TrimSpace(org)
	switch {
	case domain != "" && org != "":
		return graph.Asset{}, errors.New("give a domain or an organization, not both")
	case domain != "":
		res, err := g.ResolveAsset(ctx, graph.AssetSelector{Type: "FQDN", Field: "name", Value: domain}, 2)
		if err != nil {
			return graph.Asset{}, err
		}
		if len(res.Candidates) != 1 {
			return graph.Asset{}, fmt.Errorf("%s is not a stored domain name", domain)
		}
		return res.Candidates[0].Asset, nil
	case org != "":
		res, err := graph.ResolveOrSuggest(ctx, g, org, 5)
		if err != nil {
			return graph.Asset{}, err
		}
		if res.Status != graph.StatusMatched || res.Match == nil {
			return graph.Asset{}, fmt.Errorf("%q does not name exactly one stored organization; "+
				"resolve the organization first", org)
		}
		return *res.Match, nil
	}
	return graph.Asset{}, errors.New("a domain or an organization is required: whose documents to read")
}

// DocumentRunOptions are the settings of one documents run.
type DocumentRunOptions struct {
	Model   llm.Model
	ModelID string
	// ModelTimeout is the time one model request may take; the model client
	// applies it to each chunk.
	ModelTimeout time.Duration
	// ChunkChars is how much text one model request reads (default 12000).
	ChunkChars int
	// MaxChunks bounds the chunks of one document read in one reading
	// (options.ai.documents.max_chunks), and DocumentTimeout the time spent
	// on it (options.ai.documents.document_timeout); the next reading
	// continues where it stopped. 0 sets no bound.
	MaxChunks       int
	DocumentTimeout time.Duration
	// Max bounds the documents read in one run; 0 reads them all.
	Max int
	// Reread reads documents again even when their version was read,
	// undoing the earlier readings first.
	Reread bool
	// DryRun reads and validates but stores nothing.
	DryRun bool
	// Actor is who undoes earlier readings when Reread is set.
	Actor string
	// Fetcher gets a document's text; nil fetches it over HTTP, reading a
	// scanned document's pages with Pages.
	Fetcher DocumentFetcher
	Pages   PageReader
	// Schema gives the relationship semantics the documents are found by;
	// nil uses the OAM catalog.
	Schema graph.SchemaCatalog
	// OnChunk is called after each chunk of a document is read, so a long
	// document shows progress.
	OnChunk func()
	// Skip, when set, leaves out the Files it returns true for, without
	// counting them as remaining: documents that failed earlier in an
	// enumeration and would fail again.
	Skip func(fileID string) bool
}

// Why a document could not be read, as DocumentResult.Failure.
const (
	// FailureUnsupported is a URL whose type Amass does not read.
	FailureUnsupported = "unsupported"
	// FailureFetch is a download that failed: an HTTP status, a network
	// error, a timeout.
	FailureFetch = "fetch"
	// FailureTooLarge is a document longer than the documents rules allow.
	FailureTooLarge = "too_large"
	// FailureExtract is a document whose text could not be extracted.
	FailureExtract = "extract"
	// FailureModelTimeout is a model request that ran out of time.
	FailureModelTimeout = "model_timeout"
	// FailureModel is any other failed model request.
	FailureModel = "model"
)

// documentError is a document that could not be read, with why.
type documentError struct {
	kind string
	err  error
}

func (e *documentError) Error() string { return e.err.Error() }
func (e *documentError) Unwrap() error { return e.err }

// failureKind returns why a document could not be read. An error that does
// not say (a custom Fetcher's) is a failed fetch.
func failureKind(err error) string {
	var de *documentError
	if errors.As(err, &de) {
		return de.kind
	}
	return FailureFetch
}

// modelFailure tells a model request that ran out of time from one that
// failed otherwise.
func modelFailure(err error) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &ne) && ne.Timeout()) {
		return FailureModelTimeout
	}
	return FailureModel
}

// retryable reports whether a failure may pass on another attempt: a model
// that was busy or a server that was down, not a document that cannot be
// read.
func retryable(kind string) bool {
	return kind == FailureModelTimeout || kind == FailureModel || kind == FailureFetch
}

// DocumentResult is what one run did with one document. It holds counts, not
// document text, so it can be shown to any client.
type DocumentResult struct {
	URL        string `json:"url"`
	FileID     string `json:"file_id"`
	SHA256     string `json:"sha256,omitempty"`
	Category   string `json:"category,omitempty"`
	Chunks     int    `json:"chunks,omitempty"`
	Statements int    `json:"statements"`
	Rejected   int    `json:"rejected,omitempty"`
	ReadingID  string `json:"reading_id,omitempty"`
	// Through is where the reading stopped at MaxChunks or DocumentTimeout;
	// the document's next reading continues there.
	Through int    `json:"through,omitempty"`
	Error   string `json:"error,omitempty"`
	// Failure is why the document could not be read (Failure* kinds).
	Failure string `json:"failure,omitempty"`
	// Stale reports the document's own dates older than
	// lens.DocumentStaleAge: its findings are stored, but give no leads.
	Stale bool `json:"stale,omitempty"`
	// Stored is what was (or, in a dry run, would be) stored; it quotes the
	// document, so callers show it only where document text may be shown.
	Stored []review.StoredStatement `json:"-"`
}

// DocumentRun is the outcome of one documents run.
type DocumentRun struct {
	Documents []DocumentResult `json:"documents"`
	Read      int              `json:"read"`
	// Skipped counts documents whose version was already read.
	Skipped int `json:"skipped"`
	// Remaining counts documents left for another run: past Max, or read
	// only in part (Partial).
	Remaining  int  `json:"remaining"`
	Partial    int  `json:"partial,omitempty"`
	Failed     int  `json:"failed"`
	Statements int  `json:"statements"`
	Rejected   int  `json:"rejected"`
	DryRun     bool `json:"dry_run,omitempty"`
	// Failures counts the failed documents by why (Failure* kinds).
	Failures map[string]int `json:"failures,omitempty"`
}

// ReadDocuments has the document model read the documents the root publishes,
// all of each document's text, and stores the findings that pass validation on
// each File as doc_statement properties, journaled so each reading can be
// undone. The Asset Database keeps no copy of a document: each one is fetched
// again (from the archive copy the engine read, when it read one), its text
// extracted in memory, and the version's SHA-256 recorded, so a version is
// read once wherever it was found unless opts.Reread is set. Documents past
// opts.Max are counted as Remaining, so another run continues where this one
// stopped.
func ReadDocuments(ctx context.Context, g graph.Graph, store review.DocumentStatementStore, j *review.Journal,
	root graph.Asset, opts DocumentRunOptions) (DocumentRun, error) {
	run := DocumentRun{DryRun: opts.DryRun}
	if opts.Model == nil {
		return run, errors.New("no document model is configured (options.ai.documents)")
	}
	if opts.Actor == "" {
		opts.Actor = review.InferenceSource + " (reread)"
	}
	if opts.Fetcher == nil {
		opts.Fetcher = HTTPFetcher{Pages: opts.Pages}
	}
	if opts.Schema == nil {
		opts.Schema = oamrepo.Catalog{}
	}

	sources, err := lens.DocumentSources(ctx, g, opts.Schema, root, lens.LensLimits{})
	if err != nil {
		return run, err
	}
	read, progress, err := readState(j)
	if err != nil {
		return run, err
	}
	// engines on one database read each version once: the one holding its
	// lease reads it, and the others leave it for later
	leases := coord.OpenLeases(store)
	// current documents first, so a run that stops early has read those
	slices.SortStableFunc(sources, func(a, b lens.DocumentSource) int {
		switch {
		case a.Stale == b.Stale:
			return 0
		case b.Stale:
			return -1
		}
		return 1
	})

	for _, src := range sources {
		if ctx.Err() != nil {
			return run, ctx.Err()
		}
		// the version the engine stored was read already (or, before
		// versions were recorded, the File has statements)
		if !opts.Reread && (read[src.SHA256] || (src.SHA256 == "" && src.Statements > 0)) {
			run.Skipped++
			continue
		}
		if opts.Skip != nil && opts.Skip(src.FileID) {
			continue
		}
		if opts.Max > 0 && run.Read+run.Failed >= opts.Max {
			run.Remaining++
			continue
		}

		res := DocumentResult{URL: src.URL, FileID: src.FileID, Stale: src.Stale}
		text, sha, err := opts.Fetcher.Document(ctx, src)
		if err != nil {
			run.fail(&res, err)
			continue
		}
		res.SHA256 = sha
		// the document changed since the engine stored it, to a version
		// already read
		if !opts.Reread && read[sha] {
			run.Skipped++
			continue
		}

		release, ok := leases.Hold(ctx, "doc:"+sha, documentLeaseTTL)
		if !ok {
			run.Remaining++
			continue
		}
		if !opts.Reread && leases != nil {
			// another engine may have just finished it
			if read, progress, err = readState(j); err != nil {
				release()
				return run, err
			}
			if read[sha] {
				release()
				run.Skipped++
				continue
			}
		}

		limits := readLimits{maxChunks: opts.MaxChunks, timeout: opts.DocumentTimeout}
		if !opts.Reread {
			limits.from = progress[sha]
		}
		reading, err := readDocument(ctx, opts.Model, opts.ModelID, src.URL, text, opts.ChunkChars, limits,
			opts.OnChunk)
		if err != nil {
			release()
			if ctx.Err() != nil {
				return run, ctx.Err()
			}
			run.fail(&res, err)
			continue
		}

		run.Read++
		res.Category, res.Chunks, res.Rejected = reading.Category, reading.Chunks, len(reading.Rejected)
		res.Through = reading.Through
		if reading.Through > 0 {
			run.Partial++
			run.Remaining++
		}
		res.Stored = reading.Stored(src.URL, sha)
		res.Statements = len(res.Stored)
		if !opts.DryRun {
			if opts.Reread {
				if err := undoReadings(ctx, store, j, src.FileID, sha, opts.Actor); err != nil {
					release()
					return run, err
				}
			}
			rec, err := review.StorePartialDocumentStatements(ctx, store, j, src.FileID, src.URL, sha, opts.ModelID,
				res.Stored, reading.Through)
			if err != nil {
				release()
				return run, err
			}
			res.ReadingID = rec.ID
			if reading.Through == 0 {
				read[sha] = true
			}
		}
		release()
		run.Statements += res.Statements
		run.Rejected += res.Rejected
		run.Documents = append(run.Documents, res)
	}

	return run, nil
}

// documentLeaseTTL is how long an engine holds a document version's lease
// unless it renews it while reading.
const documentLeaseTTL = 5 * time.Minute

// readState is the versions read and, for those read only in part, where
// their last reading stopped, which the next reading continues from.
func readState(j *review.Journal) (map[string]bool, map[string]int, error) {
	read, err := j.ReadVersions()
	if err != nil {
		return nil, nil, err
	}
	progress, err := j.VersionProgress()
	if err != nil {
		return nil, nil, err
	}
	return read, progress, nil
}

// fail records a document that could not be read, and why.
func (run *DocumentRun) fail(res *DocumentResult, err error) {
	res.Error, res.Failure = err.Error(), failureKind(err)
	run.Failed++
	if run.Failures == nil {
		run.Failures = make(map[string]int)
	}
	run.Failures[res.Failure]++
	run.Documents = append(run.Documents, *res)
}

// undoReadings undoes the stored readings of a File, and of the same version
// found elsewhere, before it is read again.
func undoReadings(ctx context.Context, store review.DocumentStatementStore, j *review.Journal, fileID, sha256,
	actor string) error {
	byFile, err := j.StoredDocumentReadings(fileID)
	if err != nil {
		return err
	}
	byVersion, err := j.StoredVersionReadings(sha256)
	if err != nil {
		return err
	}

	done := map[string]bool{}
	for _, id := range append(byFile, byVersion...) {
		if done[id] {
			continue
		}
		done[id] = true
		if err := review.UndoDocumentStatements(ctx, store, j, id, actor); err != nil {
			return err
		}
	}
	return nil
}
