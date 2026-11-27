// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package product

import (
	"context"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
)

var src = &et.Source{Name: "test", Confidence: 90}

// A versioned product is stored once by its CPE name, with its release, its
// manufacturer, and the caller's relation to the release.
func TestCreateProductAsset(t *testing.T) {
	sess := plugintest.NewSession(t)
	file := sess.Asset(t, &oamfile.File{URL: "https://www.example.com/a.pdf", Type: "application/pdf"})
	sw := Software{CPE: "cpe:2.3:a:adobe:acrobat", Name: "Adobe Acrobat", Vendor: "Adobe Inc.",
		Category: "pdf editor", Version: "10.1.8"}

	res, err := CreateProductAsset(sess, file, &oamgen.SimpleRelation{Name: "created_with"}, sw, src)
	if err != nil {
		t.Fatal(err)
	}
	p := res.Product.Asset.(*oamplat.Product)
	if p.ID != sw.CPE || p.Name != "Adobe Acrobat" || p.Type != "software" {
		t.Errorf("Product %+v", p)
	}
	if r := res.Release.Asset.(*oamplat.ProductRelease); r.Name != "Adobe Acrobat 10.1.8" || res.Target != res.Release {
		t.Errorf("release %+v, target %v", r, res.Target)
	}
	if res.Manufacturer == nil || res.Manufacturer.Asset.(*oamorg.Organization).Name == "" {
		t.Errorf("manufacturer %v", res.Manufacturer)
	}

	ctx := context.Background()
	for ent, label := range map[string]string{"file": "created_with", "product": "release", "maker": "manufacturer"} {
		from := file
		switch ent {
		case "product", "maker":
			from = res.Product
		}
		if edges, err := sess.DB().OutgoingEdges(ctx, from, time.Time{}, label); err != nil || len(edges) != 1 {
			t.Errorf("%s edges = %v, %v", label, edges, err)
		}
	}

	// a second document made with the same software converges on the Product
	// and does not add a second manufacturer
	other := sess.Asset(t, &oamfile.File{URL: "https://www.example.com/b.pdf", Type: "application/pdf"})
	sw.Version = ""
	again, err := CreateProductAsset(sess, other, &oamgen.SimpleRelation{Name: "created_with"}, sw, src)
	if err != nil || again.Product.ID != res.Product.ID || again.Target != again.Product {
		t.Errorf("second create = %+v, %v", again, err)
	}
	if edges, _ := sess.DB().OutgoingEdges(ctx, res.Product, time.Time{}, "manufacturer"); len(edges) != 1 {
		t.Errorf("manufacturer edges = %d, want 1", len(edges))
	}
}

func TestCreateProductAssetNeedsCPE(t *testing.T) {
	sess := plugintest.NewSession(t)
	if _, err := CreateProductAsset(sess, nil, nil, Software{Name: "x"}, src); err == nil {
		t.Error("a product without a CPE name was created")
	}
}
