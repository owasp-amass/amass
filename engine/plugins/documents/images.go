// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"context"
	"fmt"
	"strings"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/docmeta"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// The properties a File carries for the photos embedded in it; each value
// names the image it came from ("word/media/image1.jpeg: Canon EOS 5D").
const (
	PropImageCamera    = "doc_image_camera"
	PropImageSoftware  = "doc_image_software"
	PropImageTaken     = "doc_image_taken"
	PropImageCopyright = "doc_image_copyright"
)

// imageLeads reads the EXIF of the photos embedded in the document and stores
// what it names as OAM assets linked from the File by contains: the GPS
// position (GeoLocation, with the receiver's error as its uncertainty), the
// photographer and camera owner (Person) and the camera body's serial number
// (Identifier, so the same camera is recognized across documents). Camera,
// editing software, time taken and copyright are File properties. Each asset
// is dispatched as a lead.
//
// A photo is often not the author's own, so these say what the document
// holds, not who wrote it: people are contains, never author, and the editing
// software is not created_with, which describes the document itself.
func (d *documents) imageLeads(e *et.Event, fent *dbt.Entity, dt semantics.DocumentType, data []byte, n *leads) {
	images, err := docmeta.Images(dt.Format, data)
	if err != nil || len(images) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	rules := semantics.Documents()
	seen := map[string]bool{}
	once := func(key string) bool {
		if seen[key] {
			return false
		}
		seen[key] = true
		return true
	}

	for _, img := range images {
		x := img.EXIF
		if x.Empty() {
			continue
		}
		n.images++

		if camera := cameraName(x.Make, x.Model); camera != "" {
			d.property(ctx, e, fent, PropImageCamera, img.Name+": "+camera)
		}
		for _, p := range []struct{ name, value string }{
			{PropImageSoftware, x.Software},
			{PropImageTaken, x.Taken},
			{PropImageCopyright, x.Copyright},
		} {
			if p.value != "" {
				d.property(ctx, e, fent, p.name, img.Name+": "+p.value)
			}
		}

		if x.HasGPS {
			geo := &oamcon.GeoLocation{Latitude: x.Lat, Longitude: x.Lon, Uncertainty: x.Uncertainty}
			if geo.Valid() && once("geo:"+geo.Key()) {
				if ent := d.linkAsset(e, fent, geo); ent != nil {
					d.dispatch(e, ent, geo.Key())
					n.places++
				}
			}
		}

		for _, raw := range []string{x.Artist, x.Owner} {
			raw = strings.TrimSpace(raw)
			if raw == "" || rules.IsPlaceholderAuthor(raw) || !once("person:"+strings.ToLower(raw)) {
				continue
			}
			d.storeName(e, fent, raw, "contains", nil, n)
		}

		if id := cameraSerial(x.Make, x.Serial); id != nil && once("serial:"+id.UniqueID) {
			if ent := d.linkAsset(e, fent, id); ent != nil {
				d.dispatch(e, ent, id.UniqueID)
				n.serials++
			}
		}
	}
}

// cameraName joins the make and model, leaving out the make when the model
// already starts with it ("Canon" + "Canon EOS 5D" is "Canon EOS 5D").
func cameraName(maker, model string) string {
	maker, model = strings.TrimSpace(maker), strings.TrimSpace(model)
	switch {
	case model == "":
		return maker
	case maker == "" || strings.HasPrefix(strings.ToLower(model), strings.ToLower(maker)):
		return model
	}
	return maker + " " + model
}

// cameraSerial is the Identifier for a camera body's serial number, scoped by
// its make, since serial numbers are unique per manufacturer only. A serial
// without a make, or one of all zeros (an unset field), identifies nothing.
func cameraSerial(maker, serial string) *oamgen.Identifier {
	maker = strings.ToLower(strings.Join(strings.Fields(maker), " "))
	serial = strings.TrimSpace(serial)
	if maker == "" || serial == "" || strings.Trim(serial, "0") == "" {
		return nil
	}
	return &oamgen.Identifier{
		UniqueID: fmt.Sprintf("%s:%s:%s", oamgen.SerialNumber, maker, serial),
		ID:       serial,
		Type:     oamgen.SerialNumber,
	}
}
