// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"fmt"
	"testing"
)

// The page pictures of a scanned PDF are its JPEG streams the size of a
// page; a logo is not one.
func TestPageImages(t *testing.T) {
	jpg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0xFF, 0xD9}
	stream := func(obj, w, h int) string {
		return fmt.Sprintf("%d 0 obj\n<< /Type /XObject /Subtype /Image /Width %d /Height %d /Filter /DCTDecode "+
			"/Length %d >>\nstream\n%s\nendstream\nendobj\n", obj, w, h, len(jpg), jpg)
	}
	pdf := "%PDF-1.4\n" + stream(5, 1700, 2200) + stream(6, 120, 40) + stream(7, 850, 1100) + "%%EOF\n"

	pages, err := PageImages(FormatPDF, []byte(pdf))
	if err != nil || len(pages) != 2 {
		t.Fatalf("pages %d, %v; want the two page-sized pictures", len(pages), err)
	}
	if pages[0].MediaType != "image/jpeg" || pages[0].Data[0] != 0xFF {
		t.Errorf("page %+v", pages[0])
	}
	if _, err := PageImages(FormatOOXML, nil); err == nil {
		t.Error("an OOXML document gave page pictures")
	}
	if _, err := PageImages(FormatPDF, []byte("not a pdf")); err == nil {
		t.Error("a file that is not a PDF gave page pictures")
	}
}
