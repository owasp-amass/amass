// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package product creates Product and ProductRelease assets. A Product's
// unique_id is its CPE name (cpe:2.3:part:vendor:product), so every collector
// that stores the same software converges on one Product; a ProductRelease
// is named "<product name> <version>" and hangs off its Product by the
// release relation, and the vendor is the Product's manufacturer.
package product

import (
	"context"
	"errors"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

// Software is what a caller knows about a product: its CPE name, display
// name, vendor and category, and the release version when one is stated.
type Software struct {
	CPE      string
	Name     string
	Vendor   string
	Category string
	Version  string
}

// Result holds the assets a creation touched, for the caller to dispatch.
type Result struct {
	// Target is what obj was linked to: the release when a version is known,
	// otherwise the product.
	Target       *dbt.Entity
	Product      *dbt.Entity
	Release      *dbt.Entity
	Manufacturer *dbt.Entity
}

// CreateProductAsset creates or reuses the Product (and its ProductRelease
// when sw has a version) with src as a source, links the vendor as the
// Product's manufacturer through the shared Organization path, and, when
// obj and rel are given, records obj --rel--> release (or product). It is
// the single entry point for Product creation across the plugins; same-CPE
// creates are serialized on a canonical lock.
func CreateProductAsset(sess et.Session, obj *dbt.Entity, rel oam.Relation, sw Software, src *et.Source) (*Result, error) {
	if sw.CPE == "" || sw.Name == "" {
		return nil, errors.New("missing the product CPE name or name")
	} else if src == nil {
		return nil, errors.New("missing the source")
	}

	var res *Result
	var perr error
	_ = sess.DB().WithCanonicalLock(sess.Ctx(), "product:"+sw.CPE, func() error {
		res, perr = createLocked(sess, sw, src)
		return perr
	})
	if perr != nil {
		return nil, perr
	}

	// the manufacturer goes through the Organization path and its own lock
	if sw.Vendor != "" && !hasEdge(sess, res.Product, "manufacturer") {
		res.Manufacturer, _ = org.CreateOrgAsset(sess, res.Product,
			&oamgen.SimpleRelation{Name: "manufacturer"}, &oamorg.Organization{Name: sw.Vendor}, src)
	}

	if obj != nil && rel != nil {
		if err := link(sess, obj, rel, res.Target, src); err != nil {
			return res, err
		}
	}
	return res, nil
}

func createLocked(sess et.Session, sw Software, src *et.Source) (*Result, error) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 15*time.Second)
	defer cancel()

	pent, err := sess.DB().CreateAsset(ctx, &oamplat.Product{
		ID:       sw.CPE,
		Name:     sw.Name,
		Type:     "software",
		Category: sw.Category,
	})
	if err != nil || pent == nil {
		return nil, errors.New("failed to create the Product asset")
	}
	sourced(ctx, sess, pent, src)

	res := &Result{Target: pent, Product: pent}
	if sw.Version == "" {
		return res, nil
	}

	rent, err := sess.DB().CreateAsset(ctx, &oamplat.ProductRelease{Name: sw.Name + " " + sw.Version})
	if err != nil || rent == nil {
		return res, nil
	}
	sourced(ctx, sess, rent, src)
	if err := link(sess, pent, &oamgen.SimpleRelation{Name: "release"}, rent, src); err != nil {
		return res, nil
	}

	res.Release, res.Target = rent, rent
	return res, nil
}

func hasEdge(sess et.Session, ent *dbt.Entity, label string) bool {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	edges, err := sess.DB().OutgoingEdges(ctx, ent, time.Time{}, label)
	return err == nil && len(edges) > 0
}

func link(sess et.Session, from *dbt.Entity, rel oam.Relation, to *dbt.Entity, src *et.Source) error {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	edge, err := sess.DB().CreateEdge(ctx, &dbt.Edge{Relation: rel, FromEntity: from, ToEntity: to})
	if err != nil {
		return err
	} else if edge == nil {
		return errors.New("failed to create the edge")
	}
	_, _ = sess.DB().CreateEdgeProperty(ctx, edge, &oamgen.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
	return nil
}

func sourced(ctx context.Context, sess et.Session, ent *dbt.Entity, src *et.Source) {
	_, _ = sess.DB().CreateEntityProperty(ctx, ent, &oamgen.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
}
