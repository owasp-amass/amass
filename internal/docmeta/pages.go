// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"strconv"
)

// PageImage is a page of a scanned document, as the picture the scanner
// made of it.
type PageImage struct {
	MediaType string
	Data      []byte
}

// The media types of page pictures.
const (
	MediaJPEG = "image/jpeg"
	// MediaTIFF is a fax-encoded page (CCITT group 3 or 4) wrapped as a
	// TIFF, which OCR programs read and models generally do not.
	MediaTIFF = "image/tiff"
)

// minPageSide is the fewest pixels a side of a page picture has: a page
// scanned at a low 100 dpi is 850 by 1100, while logos and photographs set in
// a page of text are mostly smaller.
const minPageSide = 600

// pdfNumber reads a number an image dictionary gives (/Width, /Height, and
// the fax parameters /K, /Columns and /Rows).
var pdfNumber = regexp.MustCompile(`/(Width|Height|K|Columns|Rows)\s+(-?\d+)`)

// pdfBlackIs1 reads the fax parameter /BlackIs1.
var pdfBlackIs1 = regexp.MustCompile(`/BlackIs1\s+true`)

// PageImages returns the page pictures of a scanned PDF, in order: its
// image streams large enough to be a whole page that are JPEG, or CCITT fax
// (the encoding office scanners use for black-and-white pages), which is
// returned wrapped as a TIFF. Pages in another encoding (JBIG2, JPEG 2000)
// are not returned. Offline and bounded.
func PageImages(format string, data []byte) ([]PageImage, error) {
	if format != FormatPDF {
		return nil, ErrFormat
	}

	var out []PageImage
	err := pdfStreams(data, func(_ int, dict, body []byte) bool {
		nums := map[string]int{}
		for _, m := range pdfNumber.FindAllSubmatch(dict, -1) {
			nums[string(m[1])], _ = strconv.Atoi(string(m[2]))
		}
		if nums["Width"] < minPageSide || nums["Height"] < minPageSide {
			return true
		}

		switch {
		case bytes.Contains(dict, []byte("/DCTDecode")) && !bytes.Contains(dict, []byte("/FlateDecode")) &&
			len(body) >= 4 && body[0] == 0xFF && body[1] == 0xD8:
			out = append(out, PageImage{MediaType: MediaJPEG, Data: body})
		case bytes.Contains(dict, []byte("/CCITTFaxDecode")) && !bytes.Contains(dict, []byte("/FlateDecode")):
			cols, rows := nums["Width"], nums["Height"]
			if nums["Columns"] > 0 {
				cols = nums["Columns"]
			}
			if nums["Rows"] > 0 {
				rows = nums["Rows"]
			}
			out = append(out, PageImage{MediaType: MediaTIFF,
				Data: faxTIFF(body, cols, rows, nums["K"], pdfBlackIs1.Match(dict))})
		}
		return len(out) < maxImages
	})
	return out, err
}

// faxTIFF wraps CCITT fax data of a page cols by rows pixels as a one-strip
// TIFF: K < 0 is group 4, K = 0 group 3 one-dimensional and K > 0 group 3
// two-dimensional, as in a PDF's CCITTFaxDecode parameters. By default a 0
// bit is black, as a PDF's fax data has it unless BlackIs1 is set.
func faxTIFF(data []byte, cols, rows, k int, blackIs1 bool) []byte {
	compression, t4 := uint32(3), uint32(0)
	switch {
	case k < 0:
		compression = 4
	case k > 0:
		t4 = 1
	}
	photometric := uint32(1) // BlackIsZero
	if blackIs1 {
		photometric = 0 // WhiteIsZero
	}

	type entry struct {
		tag   uint16
		value uint32
	}
	const header, entrySize = 8, 12
	entries := []entry{
		{256, uint32(cols)}, // ImageWidth
		{257, uint32(rows)}, // ImageLength
		{258, 1},            // BitsPerSample
		{259, compression},  // Compression
		{262, photometric},  // PhotometricInterpretation
		{273, 0},            // StripOffsets, set below
		{277, 1},            // SamplesPerPixel
		{278, uint32(rows)}, // RowsPerStrip
		{279, uint32(len(data))},
	}
	if compression == 3 {
		entries = append(entries, entry{292, t4}) // T4Options
	}
	offset := uint32(header + 2 + len(entries)*entrySize + 4)
	entries[5].value = offset

	var b bytes.Buffer
	b.WriteString("II*\x00")
	_ = binary.Write(&b, binary.LittleEndian, uint32(header))
	_ = binary.Write(&b, binary.LittleEndian, uint16(len(entries)))
	for _, e := range entries {
		typ := uint16(4) // LONG
		if e.tag == 258 || e.tag == 259 || e.tag == 262 || e.tag == 277 {
			typ = 3 // SHORT, stored in the first two bytes of the value
		}
		_ = binary.Write(&b, binary.LittleEndian, e.tag)
		_ = binary.Write(&b, binary.LittleEndian, typ)
		_ = binary.Write(&b, binary.LittleEndian, uint32(1))
		_ = binary.Write(&b, binary.LittleEndian, e.value)
	}
	_ = binary.Write(&b, binary.LittleEndian, uint32(0)) // no next IFD
	b.Write(data)
	return b.Bytes()
}
