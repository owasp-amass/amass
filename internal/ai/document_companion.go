// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/docmeta"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// Document companion defaults.
const (
	// DefaultDocumentInterval is the time between the companion's passes.
	DefaultDocumentInterval = 30 * time.Second
	// DefaultDocumentBatch is how many documents one pass reads per target.
	DefaultDocumentBatch = 3
)

// Activity names the companion counts in a run's Activity.
const (
	ActivityDocumentsRead    = "documents_read"
	ActivityDocumentFailures = "document_failures"
	// ActivityFailurePrefix starts the counts of failed documents by why:
	// document_failures_fetch, document_failures_model_timeout, and so on
	// (the Failure* kinds).
	ActivityFailurePrefix = "document_failures_"
	// ActivityDocumentErrors counts passes that could not list a target's
	// documents (a database or lens error), which would otherwise be silent.
	ActivityDocumentErrors = "document_errors"
	ActivityStatements     = "statements"
	// ActivityChunksRead counts the chunks of documents read, so a long
	// document shows progress before it is finished.
	ActivityChunksRead   = "chunks_read"
	ActivityLeads        = "leads"
	ActivityLeadsWaiting = "leads_waiting"
	// ActivityDocumentsStale counts the documents read whose own dates are
	// older than lens.DocumentStaleAge: their findings are kept, but they
	// give no leads.
	ActivityDocumentsStale = "documents_stale"
)

// DocumentGraph is the graph the companion reads documents from: it must
// return document text as stored (no withholding) and resolve the run's
// targets.
type DocumentGraph interface {
	graph.Graph
	DocumentRootGraph
}

// DocumentCompanion has the document model read the documents a supervised
// enumeration collects while it runs, all of each document's text, stores the
// validated findings as a documents run does, and hands each asset they name
// that the engine collects from (domains, addresses, networks, organizations,
// street addresses, phones, emails, URLs) and the database does not hold to
// the run's session as a lead. The engine checks
// a lead like any other (registries, attribution); it joins the scope only if
// the engine attributes it to the target. Each lead is tagged amass-ai and
// journaled so it can be retracted. The engine itself uses no model.
type DocumentCompanion struct {
	Graph        DocumentGraph
	Store        review.DocumentLeadStore
	Journal      *review.Journal
	Model        llm.Model
	ModelID      string
	ModelTimeout time.Duration
	// Interval is the time between passes; Batch the documents read per
	// target in one pass; ChunkChars the text one model request reads.
	Interval   time.Duration
	Batch      int
	ChunkChars int
	// Fetcher gets a document's text; nil fetches it over HTTP, reading a
	// scanned document's pages with Pages.
	Fetcher DocumentFetcher
	Pages   PageReader
	// MaxLeads caps the adaptive lead budget (see allowance): 0 leaves it to
	// the confirmation rate and the run's size, a negative value submits no
	// leads (findings are still stored).
	MaxLeads int
	// Schema gives the relationship semantics; nil uses the OAM catalog.
	Schema graph.SchemaCatalog
	// Hold is the longest a run whose engine work is done is kept open for
	// this companion (options.ai.documents.hold). With it, the companion
	// stops asking to keep the run open once the documents left would not
	// be read within it; 0 makes no such estimate.
	Hold time.Duration
	// MaxChunks and DocumentTimeout bound one reading of one document
	// (options.ai.documents.max_chunks and document_timeout); a document
	// read in part is continued by the next pass or run.
	MaxChunks       int
	DocumentTimeout time.Duration
}

// companionRun is the companion's state for one run.
type companionRun struct {
	mu        sync.Mutex
	inPass    bool
	remaining int
	lastStart time.Time
	doneAt    time.Time
	// readTime is the time spent reading readDocs documents in this run,
	// to estimate how long the documents left would take
	readTime  time.Duration
	readDocs  int
	nudge     chan struct{}
	roots     map[string]graph.Asset
	seen      map[string]bool
	submitted []*submittedLead
	queue     []queuedLead
	// targets are the run's own targets, which a lead must be tied to
	// before it counts as confirmed
	targets review.LeadTargets
	// failed counts each File's failed attempts in this run, and holds the
	// last failure's kind
	failed map[string]failedDocument
}

// failedDocument is a File that could not be read during a run.
type failedDocument struct {
	kind     string
	attempts int
}

// maxDocumentAttempts is how often a run tries a document whose failure may
// pass (a busy model, a server that was down); one that cannot be read (an
// unsupported or oversized file, text that cannot be extracted) is tried
// once.
const maxDocumentAttempts = 2

// skip reports whether a File failed in a way another attempt in this run
// would repeat. Without it, documents that always fail would fill every
// pass's batch and keep the rest from being read.
func (st *companionRun) skip(fileID string) bool {
	f, ok := st.failed[fileID]
	return ok && (!retryable(f.kind) || f.attempts >= maxDocumentAttempts)
}

// Begin implements collect.Companion.
func (c *DocumentCompanion) Begin(ctx context.Context, run collect.Run, act collect.Activity) func() bool {
	if c == nil || c.Model == nil || c.Graph == nil || c.Store == nil || c.Journal == nil {
		return nil
	}

	st := &companionRun{nudge: make(chan struct{}, 1), roots: map[string]graph.Asset{}, seen: map[string]bool{},
		failed: map[string]failedDocument{}, targets: leadTargets(run.Plan)}
	interval := c.Interval
	if interval <= 0 {
		interval = DefaultDocumentInterval
	}

	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			case <-st.nudge:
			}
			c.pass(ctx, run, act, st)
		}
	}()

	// Pending: a pass is running, documents remain unread, or no pass has
	// started since the engine finished its work (the first call), so the
	// documents collected last are read before the run ends.
	return func() bool {
		st.mu.Lock()
		defer st.mu.Unlock()
		if st.doneAt.IsZero() {
			st.doneAt = time.Now()
			select {
			case st.nudge <- struct{}{}:
			default:
			}
		}

		pending := st.inPass || st.remaining > 0 || !st.lastStart.After(st.doneAt)
		if pending && st.outlastsHold(c.Hold) {
			return false
		}
		return pending
	}
}

// outlastsHold reports whether the documents left, at the pace documents
// were read in this run, would not be read within the hold: holding the run
// open for them would end it at the limit anyway, with them unread. They are
// read by the next run instead. Without a pace or a hold it reports false.
func (st *companionRun) outlastsHold(hold time.Duration) bool {
	if hold <= 0 || st.remaining == 0 || st.readDocs == 0 {
		return false
	}

	per := st.readTime / time.Duration(st.readDocs)
	return time.Since(st.doneAt)+per*time.Duration(st.remaining) > hold
}

// Finish implements collect.Finisher: when the run ends, each lead it was
// given is settled. One the engine tied to the run's targets is kept and the
// relations it led to cite the document; any other
// is retracted as expired. Then the relationships the targets' documents
// state between stored assets are recorded as review-gated proposals
// (lens.FindDocumentRelations); nothing is written until a reviewer accepts
// one.
func (c *DocumentCompanion) Finish(ctx context.Context, run collect.Run) {
	if c == nil || c.Store == nil || c.Journal == nil {
		return
	}
	_, _, _ = review.SettleDocumentLeads(ctx, c.Store, c.Journal, run.ID, leadTargets(run.Plan))
	_, _ = c.recordDocumentRelations(ctx, run)
}

// recordDocumentRelations records the relationships the run's targets'
// documents state as relation proposals, and returns how many were new.
func (c *DocumentCompanion) recordDocumentRelations(ctx context.Context, run collect.Run) (int, error) {
	if c.Graph == nil {
		return 0, nil
	}
	schema := c.Schema
	if schema == nil {
		schema = oamrepo.Catalog{}
	}

	added := 0
	for _, domain := range documentTargets(run) {
		root, err := DocumentRoot(ctx, c.Graph, domain, "")
		if err != nil {
			continue
		}
		r, err := lens.FindDocumentRelations(ctx, c.Graph, schema, root, lens.LensLimits{})
		if err != nil {
			return added, err
		}
		got, err := c.Journal.SubmitRelations(review.RelationProposals(r))
		added += len(got)
		if err != nil {
			return added, err
		}
	}
	return added, nil
}

// documentTargets returns the domains a run collects.
func documentTargets(run collect.Run) []string {
	return leadTargets(run.Plan).Domains
}

// pass reads the next unread documents of each of the run's targets and
// submits the leads their statements give.
func (c *DocumentCompanion) pass(ctx context.Context, run collect.Run, act collect.Activity, st *companionRun) {
	st.mu.Lock()
	st.inPass, st.lastStart = true, time.Now()
	st.mu.Unlock()

	remaining := 0
	defer func() {
		st.mu.Lock()
		st.inPass, st.remaining = false, remaining
		st.mu.Unlock()
	}()

	// confirmations since the last pass may have raised the budget
	c.drain(ctx, run, act, st)

	batch := c.Batch
	if batch <= 0 {
		batch = DefaultDocumentBatch
	}
	for _, domain := range documentTargets(run) {
		if ctx.Err() != nil {
			return
		}

		root, ok := st.roots[domain]
		if !ok {
			r, err := DocumentRoot(ctx, c.Graph, domain, "")
			if err != nil {
				// not stored yet early in a run; try again next pass
				continue
			}
			root, st.roots[domain] = r, r
		}

		started := time.Now()
		res, err := ReadDocuments(ctx, c.Graph, c.Store, c.Journal, root, DocumentRunOptions{Model: c.Model,
			ModelID: c.ModelID, ModelTimeout: c.ModelTimeout, ChunkChars: c.ChunkChars, Max: batch,
			MaxChunks: c.MaxChunks, DocumentTimeout: c.DocumentTimeout,
			Fetcher: c.Fetcher, Pages: c.Pages, Schema: c.Schema, OnChunk: func() { count(act, ActivityChunksRead, 1) },
			Skip: st.skip})
		if err != nil {
			if ctx.Err() == nil {
				count(act, ActivityDocumentErrors, 1)
			}
			continue
		}
		if n := res.Read + res.Failed; n > 0 {
			st.mu.Lock()
			st.readTime += time.Since(started)
			st.readDocs += n
			st.mu.Unlock()
		}
		count(act, ActivityDocumentsRead, res.Read)
		count(act, ActivityDocumentFailures, res.Failed)
		count(act, ActivityStatements, res.Statements)
		for kind, n := range res.Failures {
			count(act, ActivityFailurePrefix+kind, n)
		}
		// a model that fails every document is unavailable: do not hold the
		// run open waiting for it
		if res.Read > 0 || res.Failed == 0 {
			remaining += res.Remaining
		}

		for _, d := range res.Documents {
			if d.Failure != "" {
				f := st.failed[d.FileID]
				st.failed[d.FileID] = failedDocument{kind: d.Failure, attempts: f.attempts + 1}
				continue
			}
			// a document whose own dates are years old keeps its findings,
			// but what it names is no lead: offices, staff and vendors change
			if d.Stale {
				count(act, ActivityDocumentsStale, 1)
				continue
			}
			c.submitLeads(ctx, run, act, st, d)
		}
	}
}

// submitLeads queues the assets a document's findings name that the database
// does not hold, and submits as many as the run's lead budget allows. An
// organization the document ties to no anchor (anchoredLead) is kept as a
// finding only: a name alone gives the engine just the registries to search,
// and such leads went nowhere in practice while their failures held the
// anchored leads back. A later document that ties it to an anchor makes it a
// lead.
func (c *DocumentCompanion) submitLeads(ctx context.Context, run collect.Run, act collect.Activity,
	st *companionRun, d DocumentResult) {
	if c.MaxLeads < 0 || act.Submit == nil {
		return
	}

	anchored := anchoredOrganizations(d.Stored)
	own := targetLabels(run)
	region := "US"
	if u, err := url.Parse(d.URL); err == nil {
		region = docmeta.PhoneRegion(u.Hostname())
	}
	for _, s := range d.Stored {
		for _, l := range statementLeads(s, region) {
			if selfReference(l, own) {
				continue
			}
			if !anchoredLead(l, anchored) {
				continue
			}
			key := strings.ToLower(string(l.asset.AssetType()) + "\x00" + l.name)
			if st.seen[key] {
				continue
			}
			st.seen[key] = true
			if knownLead(ctx, c.Graph, l) {
				continue
			}
			st.queue = append(st.queue, queuedLead{lead: l, stmt: s, doc: d, key: key})
			count(act, ActivityLeadsWaiting, 1)
		}
	}
	c.drain(ctx, run, act, st)
}

// leadPredicate names how a finding named its lead.
func leadPredicate(s review.StoredStatement) string {
	switch {
	case s.Predicate != "":
		return s.Predicate
	case s.Field != "":
		return "field:" + s.Field
	}
	return "named"
}

func count(act collect.Activity, name string, n int) {
	if n != 0 && act.Count != nil {
		act.Count(name, n)
	}
}
