// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oampeop "github.com/owasp-amass/open-asset-model/people"
)

// CreatePersonAsset creates or reuses the Person p, records src as a source of
// it, and — when obj and rel are given — creates the relationship
// obj --rel--> person with src as its source. It is the single entry point for
// Person creation across the plugins.
//
// Person records converge on their full name (the Person's deterministic
// unique_id), so the create is idempotent and same-name records already collapse
// at the database. The canonical lock serializes same-name creates so concurrent
// collectors converge on one record and its source and relationship writes are
// made once, and so a future, richer person identity can dedupe here without a
// second refactor. Build the Person with FullNameToPerson for a normalized name.
func CreatePersonAsset(sess et.Session, obj *dbt.Entity, rel oam.Relation, p *oampeop.Person, src *et.Source) (*dbt.Entity, error) {
	if p == nil || p.FullName == "" {
		return nil, errors.New("missing the person name")
	} else if src == nil {
		return nil, errors.New("missing the source")
	}

	var personent *dbt.Entity
	var perr error
	_ = sess.DB().WithCanonicalLock(sess.Ctx(), "person:"+strings.ToLower(p.FullName), func() error {
		personent, perr = createPersonAssetLocked(sess, obj, rel, p, src)
		return perr
	})
	return personent, perr
}

func createPersonAssetLocked(sess et.Session, obj *dbt.Entity, rel oam.Relation, p *oampeop.Person, src *et.Source) (*dbt.Entity, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	personent, err := sess.DB().CreateAsset(ctx, p)
	if err != nil || personent == nil {
		return nil, errors.New("failed to create the Person asset")
	}

	// record this caller as a source of the Person
	AddSource(ctx, sess, personent, src)

	if obj != nil && rel != nil && obj.ID != personent.ID {
		if _, err := Relate(ctx, sess, obj, rel, personent, src); err != nil {
			return nil, err
		}
	}

	return personent, nil
}
