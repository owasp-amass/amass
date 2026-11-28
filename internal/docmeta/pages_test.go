// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// The page pictures of a scanned PDF are its JPEG and fax streams the size
// of a page, the fax ones wrapped as TIFF; a logo is not one.
func TestPageImages(t *testing.T) {
	jpg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0xFF, 0xD9}
	fax := []byte{0x26, 0xA0, 0x01, 0x00, 0x10}
	stream := func(obj, w, h int, filter string, body []byte) string {
		return fmt.Sprintf("%d 0 obj\n<< /Type /XObject /Subtype /Image /Width %d /Height %d %s "+
			"/Length %d >>\nstream\n%s\nendstream\nendobj\n", obj, w, h, filter, len(body), body)
	}
	pdf := "%PDF-1.4\n" + stream(5, 1700, 2200, "/Filter /DCTDecode", jpg) +
		stream(6, 120, 40, "/Filter /DCTDecode", jpg) +
		stream(7, 2550, 3300, "/Filter /CCITTFaxDecode /DecodeParms << /K -1 /Columns 2550 >>", fax) +
		"%%EOF\n"

	pages, err := PageImages(FormatPDF, []byte(pdf))
	if err != nil || len(pages) != 2 {
		t.Fatalf("pages %d, %v; want the two page-sized pictures", len(pages), err)
	}
	if pages[0].MediaType != MediaJPEG || pages[0].Data[0] != 0xFF {
		t.Errorf("page 1 %+v", pages[0])
	}

	tiff := pages[1]
	if tiff.MediaType != MediaTIFF || !bytes.HasPrefix(tiff.Data, []byte("II*\x00")) ||
		!bytes.HasSuffix(tiff.Data, append(fax, '\n')) {
		t.Fatalf("page 2 %s %q", tiff.MediaType, tiff.Data)
	}
	tags := map[uint16]uint32{}
	n := int(binary.LittleEndian.Uint16(tiff.Data[8:]))
	for i := 0; i < n; i++ {
		e := tiff.Data[10+12*i:]
		tags[binary.LittleEndian.Uint16(e)] = binary.LittleEndian.Uint32(e[8:])
	}
	if tags[256] != 2550 || tags[257] != 3300 || tags[259]&0xFFFF != 4 || tags[262]&0xFFFF != 1 ||
		int(tags[273]) != len(tiff.Data)-len(fax)-1 {
		t.Errorf("TIFF tags %v", tags)
	}

	if _, err := PageImages(FormatOOXML, nil); err == nil {
		t.Error("an OOXML document gave page pictures")
	}
	if _, err := PageImages(FormatPDF, []byte("not a pdf")); err == nil {
		t.Error("a file that is not a PDF gave page pictures")
	}
}
