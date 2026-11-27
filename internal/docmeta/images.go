// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"archive/zip"
	"bytes"
	"io"
	"regexp"
	"strconv"
)

// Image is an image embedded in a document whose EXIF block says something.
type Image struct {
	// Name is where it sits in the document: the package part
	// ("word/media/image1.jpeg") or the PDF stream ("stream 12").
	Name string `json:"name"`
	EXIF EXIF   `json:"exif"`
}

// The bounds on embedded images.
const (
	maxImages    = 64
	maxImageSize = 16 << 20
)

// Images returns the images embedded in a document that carry EXIF data:
// the JPEG and TIFF media parts of an OOXML package, which keep the original
// file as inserted, and the JPEG (DCTDecode) image streams of a PDF, which
// keep it when the producer did not strip it. Offline and bounded.
func Images(format string, data []byte) ([]Image, error) {
	switch format {
	case FormatPDF:
		return pdfImages(data)
	case FormatOOXML:
		return ooxmlImages(data)
	}
	return nil, ErrFormat
}

// ooxmlMedia matches the media parts that can carry EXIF.
var ooxmlMedia = regexp.MustCompile(`(?i)^(?:word|ppt|xl)/media/[^/]+\.(?:jpe?g|tiff?)$`)

func ooxmlImages(data []byte) ([]Image, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errNotOOXML
	}

	var out []Image
	read := 0
	for _, f := range zr.File {
		if read >= maxImages {
			break
		}
		if !ooxmlMedia.MatchString(f.Name) {
			continue
		}
		read++

		rc, err := f.Open()
		if err != nil {
			continue
		}
		img, err := io.ReadAll(io.LimitReader(rc, maxImageSize))
		_ = rc.Close()
		if err != nil {
			continue
		}
		if x, err := ReadEXIF(img); err == nil {
			out = append(out, Image{Name: f.Name, EXIF: x})
		}
	}
	return out, nil
}

func pdfImages(data []byte) ([]Image, error) {
	if !bytes.HasPrefix(bytes.TrimLeft(data[:min(len(data), 1024)], "\x00\r\n\t "), []byte("%PDF-")) {
		return nil, errNotPDF
	}

	var out []Image
	read := 0
	for n, loc := range streamRe.FindAllIndex(data, -1) {
		if read >= maxImages {
			break
		}
		if loc[0] >= 3 && string(data[loc[0]-3:loc[0]]) == "end" {
			continue
		}
		dictStart := bytes.LastIndex(data[max(0, loc[0]-2048):loc[0]], []byte("<<"))
		if dictStart < 0 {
			continue
		}
		dict := data[max(0, loc[0]-2048)+dictStart : loc[0]]
		// a JPEG kept whole, not one recompressed with another filter too
		if !bytes.Contains(dict, []byte("/DCTDecode")) || bytes.Contains(dict, []byte("/FlateDecode")) {
			continue
		}

		body := data[loc[1]:]
		if end := bytes.Index(body, []byte("endstream")); end >= 0 {
			body = body[:end]
		}
		if len(body) > maxImageSize || len(body) < 4 || body[0] != 0xFF || body[1] != 0xD8 {
			continue
		}
		read++
		if x, err := ReadEXIF(body); err == nil {
			out = append(out, Image{Name: "stream " + strconv.Itoa(n), EXIF: x})
		}
	}
	return out, nil
}
