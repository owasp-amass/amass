// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	"golang.org/x/net/publicsuffix"
)

// runState is what the plugin keeps about one enumeration: the documents
// fetched for each registered domain, and the URLs this run handed the
// pipeline as leads from documents.
type runState struct {
	session  et.Session
	fetched  map[string]int
	fromDocs map[string]bool
	reported map[string]bool
}

// run returns the session's state, creating it on first use, and drops the
// state of sessions that have ended.
func (d *documents) run(e *et.Event) *runState {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.runs == nil {
		d.runs = make(map[string]*runState)
	}
	for id, r := range d.runs {
		if r.session.Done() {
			delete(d.runs, id)
		}
	}

	id := e.Session.ID().String()
	r, ok := d.runs[id]
	if !ok {
		r = &runState{session: e.Session, fetched: make(map[string]int), fromDocs: make(map[string]bool),
			reported: make(map[string]bool)}
		d.runs[id] = r
	}
	return r
}

// ledFromDocument records that this run handed the URL key to the pipeline
// as a lead from a document.
func (d *documents) ledFromDocument(e *et.Event, key string) {
	r := d.run(e)

	d.mu.Lock()
	defer d.mu.Unlock()

	r.fromDocs[key] = true
}

// admit decides whether this run fetches the document at the URL key on
// host. A document named in another document read in this run is left for a
// later run, as is one past the run's limit for its registered domain. An
// admitted document counts against the limit. It returns why a document is
// left, or "" when it is admitted.
func (d *documents) admit(e *et.Event, key, host string, limit int) string {
	r := d.run(e)
	domain := registeredDomain(host)

	d.mu.Lock()
	defer d.mu.Unlock()

	if r.fromDocs[key] {
		return "named in a document read in this run"
	}
	if r.fetched[domain] >= limit {
		if !r.reported[domain] {
			r.reported[domain] = true
			e.Session.Log().Info("document limit reached for this run; later runs read the rest", "domain", domain,
				"limit", limit, slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
		}
		return "past the run's limit"
	}

	r.fetched[domain]++
	return ""
}

// registeredDomain returns the registered domain of host, or host itself
// (an IP address, or a name without a public suffix).
func registeredDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if dom, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return dom
	}
	return host
}

// storedSince reports whether the URL has a File stored since t.
func storedSince(e *et.Event, urlent *dbt.Entity, t time.Time) bool {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	edges, err := e.Session.DB().OutgoingEdges(ctx, urlent, t, "file")
	return err == nil && len(edges) > 0
}

// attemptedSince reports whether this plugin tried the URL since t, whether
// or not the document was retrieved.
func (d *documents) attemptedSince(e *et.Event, urlent *dbt.Entity, t time.Time) bool {
	return support.AssetMonitoredWithinTTL(e.Session, urlent, d.source, t)
}
