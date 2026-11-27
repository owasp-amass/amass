// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"testing"
	"unicode/utf16"
)

// tag is one IFD entry to write.
type tag struct {
	id    uint16
	typ   uint16
	count uint32
	data  []byte
}

func asciiTag(id uint16, s string) tag {
	return tag{id: id, typ: 2, count: uint32(len(s) + 1), data: append([]byte(s), 0)}
}

func rationals(order binary.ByteOrder, vals ...[2]uint32) []byte {
	b := make([]byte, 8*len(vals))
	for i, v := range vals {
		order.PutUint32(b[8*i:], v[0])
		order.PutUint32(b[8*i+4:], v[1])
	}
	return b
}

// buildTIFF lays out IFD0 and, when given, the EXIF and GPS IFDs, with the
// pointers to them, and every value that does not fit inline in a data area.
func buildTIFF(order binary.ByteOrder, ifd0, exif, gps []tag) []byte {
	ifdSize := func(tags []tag) int { return 2 + 12*len(tags) + 4 }
	n0 := len(ifd0)
	if exif != nil {
		n0++
	}
	if gps != nil {
		n0++
	}
	off0 := 8
	offExif := off0 + 2 + 12*n0 + 4
	offGPS := offExif
	if exif != nil {
		offGPS += ifdSize(exif)
	}
	dataOff := offGPS
	if gps != nil {
		dataOff += ifdSize(gps)
	}

	if exif != nil {
		v := make([]byte, 4)
		order.PutUint32(v, uint32(offExif))
		ifd0 = append(ifd0, tag{id: tagExifIFD, typ: 4, count: 1, data: v})
	}
	if gps != nil {
		v := make([]byte, 4)
		order.PutUint32(v, uint32(offGPS))
		ifd0 = append(ifd0, tag{id: tagGPSIFD, typ: 4, count: 1, data: v})
	}

	var data []byte
	writeIFD := func(tags []tag) []byte {
		b := make([]byte, 2, ifdSize(tags))
		order.PutUint16(b, uint16(len(tags)))
		for _, t := range tags {
			e := make([]byte, 12)
			order.PutUint16(e[0:], t.id)
			order.PutUint16(e[2:], t.typ)
			order.PutUint32(e[4:], t.count)
			if len(t.data) <= 4 {
				copy(e[8:], t.data)
			} else {
				order.PutUint32(e[8:], uint32(dataOff+len(data)))
				data = append(data, t.data...)
			}
			b = append(b, e...)
		}
		return append(b, 0, 0, 0, 0)
	}

	out := make([]byte, 8)
	if order == binary.LittleEndian {
		copy(out, "II")
	} else {
		copy(out, "MM")
	}
	order.PutUint16(out[2:], 42)
	order.PutUint32(out[4:], uint32(off0))
	out = append(out, writeIFD(ifd0)...)
	if exif != nil {
		out = append(out, writeIFD(exif)...)
	}
	if gps != nil {
		out = append(out, writeIFD(gps)...)
	}
	return append(out, data...)
}

// jpegWithEXIF wraps a TIFF block as a JPEG's APP1 segment.
func jpegWithEXIF(tiff []byte) []byte {
	seg := append([]byte("Exif\x00\x00"), tiff...)
	size := make([]byte, 2)
	binary.BigEndian.PutUint16(size, uint16(len(seg)+2))
	jpg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 'J', 'F'} // a short APP0 first
	jpg = append(jpg, 0xFF, 0xE1)
	jpg = append(jpg, size...)
	jpg = append(jpg, seg...)
	return append(jpg, 0xFF, 0xDA, 0x00, 0x02, 0xFF, 0xD9)
}

func sampleEXIF(order binary.ByteOrder) []byte {
	return buildTIFF(order,
		[]tag{asciiTag(tagMake, "Canon"), asciiTag(tagModel, "Canon EOS 5D Mark IV"),
			asciiTag(tagSoftware, "Adobe Photoshop 24.0 (Windows)"), asciiTag(tagArtist, "Jane Q. Doe")},
		[]tag{asciiTag(tagDateTimeOriginal, "2019:05:06 07:08:09"), asciiTag(tagCameraOwnerName, "Jane Doe"),
			asciiTag(tagBodySerialNumber, "032021001234")},
		[]tag{asciiTag(tagGPSLatitudeRef, "N"),
			{id: tagGPSLatitude, typ: 5, count: 3, data: rationals(order, [2]uint32{42, 1}, [2]uint32{28, 1}, [2]uint32{712, 100})},
			asciiTag(tagGPSLongitudeRef, "W"),
			{id: tagGPSLongitude, typ: 5, count: 3, data: rationals(order, [2]uint32{75, 1}, [2]uint32{3, 1}, [2]uint32{5040, 100})},
			{id: tagGPSHPosError, typ: 5, count: 1, data: rationals(order, [2]uint32{125, 10})}},
	)
}

// Every field is read from a JPEG's EXIF block, in either byte order.
func TestReadEXIF(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.BigEndian, binary.LittleEndian} {
		x, err := ReadEXIF(jpegWithEXIF(sampleEXIF(order)))
		if err != nil {
			t.Fatalf("%v: %v", order, err)
		}
		if x.Make != "Canon" || x.Model != "Canon EOS 5D Mark IV" || x.Software != "Adobe Photoshop 24.0 (Windows)" ||
			x.Artist != "Jane Q. Doe" || x.Owner != "Jane Doe" || x.Serial != "032021001234" ||
			x.Taken != "2019:05:06 07:08:09" {
			t.Errorf("%v: %+v", order, x)
		}
		if !x.HasGPS || math.Abs(x.Lat-42.46864) > 1e-4 || math.Abs(x.Lon-(-75.064)) > 1e-4 {
			t.Errorf("%v: GPS %v %v %v", order, x.HasGPS, x.Lat, x.Lon)
		}
		if x.Uncertainty != 12.5 {
			t.Errorf("%v: uncertainty %v", order, x.Uncertainty)
		}
	}
}

// A TIFF file is read directly; the Windows author is the fallback artist.
func TestReadEXIFTIFFAndXPAuthor(t *testing.T) {
	u := utf16.Encode([]rune("John Smith"))
	b := make([]byte, 2*len(u)+2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	tiff := buildTIFF(binary.LittleEndian, []tag{{id: tagXPAuthor, typ: 1, count: uint32(len(b)), data: b}}, nil, nil)

	x, err := ReadEXIF(tiff)
	if err != nil || x.Artist != "John Smith" {
		t.Errorf("XPAuthor artist %q, %v", x.Artist, err)
	}
}

// Images without EXIF, malformed blocks and 0,0 positions give nothing.
func TestReadEXIFRejects(t *testing.T) {
	if _, err := ReadEXIF([]byte{0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02}); err == nil {
		t.Error("a JPEG without EXIF read")
	}
	if _, err := ReadEXIF([]byte("not an image")); err == nil {
		t.Error("garbage read")
	}
	truncated := jpegWithEXIF(sampleEXIF(binary.BigEndian))
	if _, err := ReadEXIF(truncated[:40]); err == nil {
		t.Error("a truncated block read")
	}

	order := binary.BigEndian
	zero := buildTIFF(order, []tag{asciiTag(tagMake, "Canon")}, nil, []tag{
		{id: tagGPSLatitude, typ: 5, count: 3, data: rationals(order, [2]uint32{0, 1}, [2]uint32{0, 1}, [2]uint32{0, 1})},
		{id: tagGPSLongitude, typ: 5, count: 3, data: rationals(order, [2]uint32{0, 1}, [2]uint32{0, 1}, [2]uint32{0, 1})}})
	if x, err := ReadEXIF(zero); err != nil || x.HasGPS {
		t.Errorf("0,0 taken as a position: %+v %v", x, err)
	}
}

// Images are read from an OOXML package's media parts and a PDF's JPEG
// streams; images without EXIF are left out.
func TestImages(t *testing.T) {
	jpg := jpegWithEXIF(sampleEXIF(binary.BigEndian))

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string][]byte{
		"word/media/image1.jpeg": jpg,
		"word/media/image2.png":  []byte("\x89PNG"),
		"word/media/image3.jpg":  {0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02},
		"word/document.xml":      []byte("<w:document/>"),
	} {
		w, _ := zw.Create(name)
		_, _ = w.Write(body)
	}
	_ = zw.Close()

	imgs, err := Images(FormatOOXML, buf.Bytes())
	if err != nil || len(imgs) != 1 || imgs[0].Name != "word/media/image1.jpeg" || imgs[0].EXIF.Make != "Canon" {
		t.Errorf("OOXML images %+v, %v", imgs, err)
	}

	pdf := fmt.Sprintf("%%PDF-1.4\n5 0 obj\n<< /Type /XObject /Subtype /Image /Filter /DCTDecode /Length %d >>\n"+
		"stream\n%s\nendstream\nendobj\n%%%%EOF\n", len(jpg), jpg)
	imgs, err = Images(FormatPDF, []byte(pdf))
	if err != nil || len(imgs) != 1 || !imgs[0].EXIF.HasGPS {
		t.Errorf("PDF images %+v, %v", imgs, err)
	}
}
