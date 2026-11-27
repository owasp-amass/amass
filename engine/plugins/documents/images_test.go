// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
)

// exifEntry is one TIFF IFD entry, its value already encoded big-endian.
type exifEntry struct {
	id, typ uint16
	count   uint32
	val     []byte
}

func exifASCII(id uint16, s string) exifEntry {
	return exifEntry{id: id, typ: 2, count: uint32(len(s) + 1), val: append([]byte(s), 0)}
}

func exifRationals(id uint16, vals ...[2]uint32) exifEntry {
	b := make([]byte, 0, 8*len(vals))
	for _, v := range vals {
		b = binary.BigEndian.AppendUint32(b, v[0])
		b = binary.BigEndian.AppendUint32(b, v[1])
	}
	return exifEntry{id: id, typ: 5, count: uint32(len(vals)), val: b}
}

// exifJPEG builds a JPEG whose APP1 block holds a big-endian TIFF with IFD0,
// an EXIF IFD and a GPS IFD, in that order, followed by their values.
func exifJPEG(ifd0, exif, gps []exifEntry) []byte {
	size := func(n int) int { return 2 + 12*n + 4 }
	offExif := 8 + size(len(ifd0)+2)
	offGPS := offExif + size(len(exif))
	dataOff := offGPS + size(len(gps))

	ptr := func(id uint16, off int) exifEntry {
		return exifEntry{id: id, typ: 4, count: 1, val: binary.BigEndian.AppendUint32(nil, uint32(off))}
	}
	ifd0 = append(ifd0, ptr(0x8769, offExif), ptr(0x8825, offGPS))

	var data []byte
	writeIFD := func(entries []exifEntry) []byte {
		slices.SortFunc(entries, func(a, b exifEntry) int { return int(a.id) - int(b.id) })
		out := binary.BigEndian.AppendUint16(nil, uint16(len(entries)))
		for _, e := range entries {
			out = binary.BigEndian.AppendUint16(out, e.id)
			out = binary.BigEndian.AppendUint16(out, e.typ)
			out = binary.BigEndian.AppendUint32(out, e.count)
			if len(e.val) <= 4 {
				v := make([]byte, 4)
				copy(v, e.val)
				out = append(out, v...)
				continue
			}
			out = binary.BigEndian.AppendUint32(out, uint32(dataOff+len(data)))
			data = append(data, e.val...)
		}
		return binary.BigEndian.AppendUint32(out, 0)
	}

	tiff := []byte{'M', 'M', 0, 42, 0, 0, 0, 8}
	tiff = append(tiff, writeIFD(ifd0)...)
	tiff = append(tiff, writeIFD(exif)...)
	tiff = append(tiff, writeIFD(gps)...)
	tiff = append(tiff, data...)

	app1 := append([]byte("Exif\x00\x00"), tiff...)
	jpg := []byte{0xFF, 0xD8, 0xFF, 0xE1}
	jpg = binary.BigEndian.AppendUint16(jpg, uint16(len(app1)+2))
	jpg = append(jpg, app1...)
	return append(jpg, 0xFF, 0xD9)
}

// photoDoc is a Word document holding one photo with EXIF.
func photoDoc(t *testing.T) string {
	t.Helper()
	img := exifJPEG(
		[]exifEntry{exifASCII(0x010F, "Canon"), exifASCII(0x0110, "Canon EOS 5D Mark IV"),
			exifASCII(0x0131, "Adobe Photoshop 24.0"), exifASCII(0x013B, "Jane Q. Doe")},
		[]exifEntry{exifASCII(0x9003, "2019:05:06 07:08:09"), exifASCII(0xA431, "032021001234")},
		[]exifEntry{exifASCII(0x0001, "N"), exifRationals(0x0002, [2]uint32{42, 1}, [2]uint32{28, 1}, [2]uint32{712, 100}),
			exifASCII(0x0003, "W"), exifRationals(0x0004, [2]uint32{75, 1}, [2]uint32{3, 1}, [2]uint32{5040, 100}),
			exifRationals(0x001F, [2]uint32{125, 10})},
	)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, part := range []struct {
		name string
		body []byte
	}{
		{"docProps/core.xml", []byte(`<cp:coreProperties xmlns:cp="cp" xmlns:dc="dc"><dc:creator>John Smith</dc:creator></cp:coreProperties>`)},
		{"word/document.xml", []byte(`<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Campus tour</w:t></w:r></w:p></w:body></w:document>`)},
		{"word/media/image1.jpeg", img},
	} {
		w, err := zw.Create(part.name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(part.body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// An embedded photo's EXIF gives the File a GeoLocation (with the receiver's
// error as its uncertainty), the photographer as a contained Person (not an
// author), and the camera's serial number; each is dispatched as a lead.
func TestImageLeads(t *testing.T) {
	f := newFixture(t, http.StatusOK, photoDoc(t))
	raw := "https://www.example.com/tour/tour.docx"
	if err := f.d.check(f.event(t, raw)); err != nil {
		t.Fatal(err)
	}
	fent := f.file(t, raw)
	if fent == nil {
		t.Fatal("no File stored")
	}

	got := neighbors(t, f, fent, "contains")
	for _, want := range []string{"42.468644,-75.064000", "serial:canon:032021001234"} {
		if !slices.Contains(got, want) {
			t.Errorf("contains %v, missing %s", got, want)
		}
	}
	var photographer bool
	for _, k := range got {
		photographer = photographer || strings.Contains(k, "Jane")
	}
	if !photographer {
		t.Errorf("contains %v, missing the photographer", got)
	}
	for _, k := range neighbors(t, f, fent, "author") {
		if strings.Contains(k, "Jane") {
			t.Errorf("the photographer was made an author: %v", k)
		}
	}

	ctx := context.Background()
	geos, err := f.sess.DB().FindEntitiesByContent(ctx, oam.GeoLocation, time.Time{}, 0,
		contentFilter("unique_id", "42.468644,-75.064000"))
	if err != nil || len(geos) != 1 {
		t.Fatalf("GeoLocation lookup %v, %v", geos, err)
	}
	if g := geos[0].Asset.(*oamcon.GeoLocation); math.Abs(g.Uncertainty-12.5) > 1e-9 {
		t.Errorf("GeoLocation %+v", g)
	}

	p := props(t, f, fent)
	if p[PropImageCamera] != "word/media/image1.jpeg: Canon EOS 5D Mark IV" ||
		p[PropImageTaken] != "word/media/image1.jpeg: 2019:05:06 07:08:09" ||
		p[PropImageSoftware] != "word/media/image1.jpeg: Adobe Photoshop 24.0" {
		t.Errorf("image properties %v", p)
	}

	names := f.disp.Names()
	for _, want := range []string{"42.468644,-75.064000", "serial:canon:032021001234"} {
		if !slices.Contains(names, want) {
			t.Errorf("dispatched %v, missing %s", names, want)
		}
	}
}

func TestCameraName(t *testing.T) {
	for _, tc := range []struct{ maker, model, want string }{
		{"Canon", "Canon EOS 5D", "Canon EOS 5D"},
		{"NIKON CORPORATION", "NIKON D850", "NIKON CORPORATION NIKON D850"},
		{"Apple", "iPhone 12", "Apple iPhone 12"},
		{"", "iPhone 12", "iPhone 12"},
		{"Apple", "", "Apple"},
	} {
		if got := cameraName(tc.maker, tc.model); got != tc.want {
			t.Errorf("cameraName(%q, %q) = %q, want %q", tc.maker, tc.model, got, tc.want)
		}
	}
}

func TestCameraSerial(t *testing.T) {
	if id := cameraSerial("Canon ", "032021001234"); id == nil || id.UniqueID != "serial:canon:032021001234" {
		t.Errorf("serial %+v", id)
	}
	for _, tc := range []struct{ maker, serial string }{{"", "123"}, {"Canon", ""}, {"Canon", "0000"}} {
		if id := cameraSerial(tc.maker, tc.serial); id != nil {
			t.Errorf("cameraSerial(%q, %q) = %+v, want none", tc.maker, tc.serial, id)
		}
	}
}
