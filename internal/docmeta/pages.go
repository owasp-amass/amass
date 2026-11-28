// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"regexp"
	"strconv"
)

// PageImage is a page of a scanned document, as the picture the scanner
// made of it.
type PageImage struct {
	MediaType string
	Data      []byte
}

// minPageSide is the fewest pixels a side of a page picture has: a page
// scanned at a low 100 dpi is 850 by 1100, while logos and photographs set in
// a page of text are mostly smaller.
const minPageSide = 600

// pdfDimension reads an image dictionary's /Width or /Height.
var pdfDimension = regexp.MustCompile(`/(Width|Height)\s+(\d+)`)

// PageImages returns the page pictures of a scanned PDF: its JPEG image
// streams large enough to be a whole page, in order. Pages stored in another
// image encoding (CCITT fax, JBIG2, JPEG 2000) are not returned. Offline and
// bounded.
func PageImages(format string, data []byte) ([]PageImage, error) {
	if format != FormatPDF {
		return nil, ErrFormat
	}

	var out []PageImage
	err := pdfJPEGs(data, func(_ int, dict, body []byte) bool {
		sides := map[string]int{}
		for _, m := range pdfDimension.FindAllSubmatch(dict, -1) {
			sides[string(m[1])], _ = strconv.Atoi(string(m[2]))
		}
		if sides["Width"] >= minPageSide && sides["Height"] >= minPageSide {
			out = append(out, PageImage{MediaType: "image/jpeg", Data: body})
		}
		return true
	})
	return out, err
}
