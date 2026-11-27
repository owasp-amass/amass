// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// StoreFingerprint records value as a shared Identifier{idType:value} and a
// "fingerprint" edge from entity to it, both tagged with src. Assets and hosts
// that carry the same value share the one Identifier, so they sit one hop apart
// in the graph and can be pivoted on: an origin server behind a CDN by its
// favicon hash, services on the same stack by their JARM, the pages of one
// owner by a shared analytics identifier. The id_type names the fingerprint and
// the id is the value, the way JARM was stored by value before. An empty value
// is ignored; it reports whether the fingerprint was stored.
//
// A default server or framework value (a stock favicon, a default page title)
// appears on many unrelated hosts, so materializing it would make one hub that
// every such host links to and that grows without bound across the shared
// database; such cited defaults are skipped (semantics.IsDefaultFingerprint).
// A value that distinguishes an owner is recorded in full, however many hosts
// share it; the ownership lens bounds over-common values at read time.
func StoreFingerprint(e *et.Event, entity *dbt.Entity, src *et.Source, idType, value string) bool {
	if entity == nil || src == nil || idType == "" || value == "" {
		return false
	}
	if semantics.IsDefaultFingerprint(idType, value) {
		return false
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	ident, err := e.Session.DB().CreateAsset(ctx, &oamgen.Identifier{
		UniqueID: idType + ":" + value,
		ID:       value,
		Type:     idType,
	})
	if err != nil || ident == nil {
		return false
	}
	AddSource(ctx, e.Session, ident, src)

	if _, err := Relate(ctx, e.Session, entity, &oamgen.SimpleRelation{Name: "fingerprint"}, ident, src); err != nil {
		return false
	}

	return true
}
