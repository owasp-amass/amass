// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"sync"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/asset-db/repository"
)

// journals holds one review journal per path and database, shared by every
// plugin that records AI decisions, so their appends to a file are
// serialized together and a journal kept in a database reads it once.
var journals sync.Map

type journalKey struct {
	path string
	db   repository.Repository
}

// ReviewJournal returns the review journal the session's AI decisions are
// recorded in, or nil when attribution, and so the journal, is off. lookup
// resolves environment variables (os.LookupEnv outside tests).
func ReviewJournal(sess et.Session, lookup func(string) (string, bool)) *review.Journal {
	mode, path, err := sess.Config().AIAttribution(lookup)
	if err != nil || mode == config.AttributionOff || path == "" {
		return nil
	}
	db := sess.DB()
	if j, ok := journals.Load(journalKey{path, db}); ok {
		return j.(*review.Journal)
	}
	j, _ := journals.LoadOrStore(journalKey{path, db}, review.OpenJournal(path, db))
	return j.(*review.Journal)
}
