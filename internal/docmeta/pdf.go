// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"errors"
	"html"
	"io"
	"regexp"
	"strings"
	"unicode/utf16"
)

// Bounds on the work done for one PDF: modern PDFs keep their document
// information in compressed object streams, which are inflated to find it,
// but never more than these.
const (
	maxPDFStreams       = 256
	maxPDFStreamInflate = 4 << 20
	maxPDFTotalInflate  = 32 << 20
)

// errNotPDF is returned for data that does not start like a PDF.
var errNotPDF = errors.New("docmeta: not a PDF")

// extractPDF reads the document information dictionary (/Author, /Creator,
// /Producer, /Title, /CreationDate, /ModDate) and the XMP metadata packet,
// from the raw file and from its compressed streams. The Info dictionary is
// preferred; XMP fills what it lacks.
func extractPDF(data []byte) (Metadata, error) {
	var m Metadata
	if !bytes.HasPrefix(bytes.TrimLeft(data[:min(len(data), 1024)], "\x00\r\n\t "), []byte("%PDF-")) {
		return m, errNotPDF
	}

	chunks := append([][]byte{data}, inflatedStreams(data)...)
	for _, c := range chunks {
		readInfo(c, &m)
	}
	for _, c := range chunks {
		readXMP(c, &m)
	}

	m.Created = normalizeDate(m.Created)
	m.Modified = normalizeDate(m.Modified)
	return m, nil
}

// infoKeys map the Info dictionary keys to the fields they fill.
var infoKeys = []struct {
	key   string
	field func(*Metadata) *string
}{
	{"/Title", func(m *Metadata) *string { return &m.Title }},
	{"/Author", func(m *Metadata) *string { return &m.Author }},
	{"/Creator", func(m *Metadata) *string { return &m.Creator }},
	{"/Producer", func(m *Metadata) *string { return &m.Producer }},
	{"/CreationDate", func(m *Metadata) *string { return &m.Created }},
	{"/ModDate", func(m *Metadata) *string { return &m.Modified }},
}

// infoMarkers are keys only a document information dictionary carries, so a
// dictionary holding one is read as the Info dictionary. Other dictionaries
// also use /Title (bookmarks), which must not be read as the document's.
var infoMarkers = [][]byte{[]byte("/Producer"), []byte("/CreationDate"), []byte("/ModDate"), []byte("/Author")}

// readInfo fills empty fields from the document information dictionaries in
// data.
func readInfo(data []byte, m *Metadata) {
	for _, dict := range infoDicts(data) {
		for _, k := range infoKeys {
			f := k.field(m)
			if *f != "" {
				continue
			}
			if s, ok := keyString(dict, []byte(k.key)); ok {
				*f = s
			}
		}
	}
}

// infoDicts returns the dictionaries in data that hold an Info marker key:
// from the "<<" before the marker to the ">>" after it.
func infoDicts(data []byte) [][]byte {
	var out [][]byte
	seen := map[int]bool{}
	for _, marker := range infoMarkers {
		for off := 0; off < len(data) && len(out) < 16; {
			i := bytes.Index(data[off:], marker)
			if i < 0 {
				break
			}
			at := off + i
			off = at + len(marker)

			start := bytes.LastIndex(data[max(0, at-4096):at], []byte("<<"))
			if start < 0 {
				continue
			}
			start += max(0, at-4096)
			if seen[start] {
				continue
			}
			end := bytes.Index(data[at:min(len(data), at+8192)], []byte(">>"))
			if end < 0 {
				continue
			}

			seen[start] = true
			out = append(out, data[start:at+end])
		}
	}

	return out
}

// keyString returns the string value of the first occurrence of key in a
// dictionary.
func keyString(dict, key []byte) (string, bool) {
	for off := 0; off < len(dict); {
		i := bytes.Index(dict[off:], key)
		if i < 0 {
			return "", false
		}
		at := off + i + len(key)
		off = at
		// a longer name sharing the prefix (/Authors) is another key
		if at < len(dict) && isNameChar(dict[at]) {
			continue
		}
		if s, ok := pdfStringAt(dict, at); ok && strings.TrimSpace(s) != "" {
			return s, true
		}
	}

	return "", false
}

func isNameChar(b byte) bool {
	return b > ' ' && !bytes.ContainsRune([]byte("()<>[]{}/%"), rune(b))
}

// pdfStringAt reads the literal "(…)" or hex "<…>" string that follows a key,
// skipping white space.
func pdfStringAt(data []byte, i int) (string, bool) {
	for i < len(data) && (data[i] == ' ' || data[i] == '\r' || data[i] == '\n' || data[i] == '\t') {
		i++
	}
	if i >= len(data) {
		return "", false
	}

	switch {
	case data[i] == '(':
		raw, ok := literalString(data[i+1:])
		return decodePDFText(raw), ok
	case data[i] == '<' && (i+1 >= len(data) || data[i+1] != '<'):
		end := bytes.IndexByte(data[i+1:], '>')
		if end < 0 || end > 4*maxField {
			return "", false
		}
		h := bytes.Map(func(r rune) rune {
			if strings.ContainsRune(" \r\n\t", r) {
				return -1
			}
			return r
		}, data[i+1:i+1+end])
		if len(h)%2 == 1 {
			h = append(h, '0')
		}
		raw, err := hex.DecodeString(string(h))
		return decodePDFText(raw), err == nil
	}

	return "", false
}

// literalString reads a PDF literal string's bytes up to its closing
// parenthesis, honoring nested parentheses and backslash escapes.
func literalString(data []byte) ([]byte, bool) {
	var out []byte
	depth := 0
	for i := 0; i < len(data) && len(out) < 4*maxField; i++ {
		c := data[i]
		switch {
		case c == '\\' && i+1 < len(data):
			i++
			switch e := data[i]; e {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '\r', '\n':
				// a line continuation
				if e == '\r' && i+1 < len(data) && data[i+1] == '\n' {
					i++
				}
			default:
				if e >= '0' && e <= '7' {
					v := int(e - '0')
					for n := 0; n < 2 && i+1 < len(data) && data[i+1] >= '0' && data[i+1] <= '7'; n++ {
						i++
						v = v*8 + int(data[i]-'0')
					}
					out = append(out, byte(v))
				} else {
					out = append(out, e)
				}
			}
		case c == '(':
			depth++
			out = append(out, c)
		case c == ')':
			if depth == 0 {
				return out, true
			}
			depth--
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}

	return out, false
}

// decodePDFText decodes a PDF text string: UTF-16 with a byte-order mark, or
// PDFDocEncoding, read as Latin-1 (they agree on the printable range).
func decodePDFText(raw []byte) string {
	if len(raw) >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
		var u []uint16
		for i := 2; i+1 < len(raw); i += 2 {
			u = append(u, uint16(raw[i])<<8|uint16(raw[i+1]))
		}
		return string(utf16.Decode(u))
	}
	if len(raw) >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF {
		return string(raw[3:])
	}

	r := make([]rune, len(raw))
	for i, b := range raw {
		r[i] = rune(b)
	}
	return string(r)
}

// xmpRe find the XMP fields, as elements or attributes. Creator and title
// hold an rdf:Alt/Seq list whose first item is read.
var xmpFields = []struct {
	re    *regexp.Regexp
	field func(*Metadata) *string
}{
	{regexp.MustCompile(`(?s)<dc:title>.*?<rdf:li[^>]*>(.*?)</rdf:li>`), func(m *Metadata) *string { return &m.Title }},
	{regexp.MustCompile(`(?s)<dc:creator>.*?<rdf:li[^>]*>(.*?)</rdf:li>`), func(m *Metadata) *string { return &m.Author }},
	{regexp.MustCompile(`(?s)<xmp:CreatorTool>(.*?)</xmp:CreatorTool>|xmp:CreatorTool="([^"]*)"`),
		func(m *Metadata) *string { return &m.Creator }},
	{regexp.MustCompile(`(?s)<pdf:Producer>(.*?)</pdf:Producer>|pdf:Producer="([^"]*)"`),
		func(m *Metadata) *string { return &m.Producer }},
	{regexp.MustCompile(`(?s)<xmp:CreateDate>(.*?)</xmp:CreateDate>|xmp:CreateDate="([^"]*)"`),
		func(m *Metadata) *string { return &m.Created }},
	{regexp.MustCompile(`(?s)<xmp:ModifyDate>(.*?)</xmp:ModifyDate>|xmp:ModifyDate="([^"]*)"`),
		func(m *Metadata) *string { return &m.Modified }},
}

// readXMP fills empty fields from an XMP metadata packet in data.
func readXMP(data []byte, m *Metadata) {
	start := bytes.Index(data, []byte("<x:xmpmeta"))
	if start < 0 {
		start = bytes.Index(data, []byte("<rdf:RDF"))
	}
	if start < 0 {
		return
	}
	end := bytes.Index(data[start:], []byte("</x:xmpmeta>"))
	if end < 0 {
		end = min(len(data)-start, 256<<10)
	}
	packet := data[start : start+end]

	for _, x := range xmpFields {
		f := x.field(m)
		if *f != "" {
			continue
		}
		if sm := x.re.FindSubmatch(packet); sm != nil {
			for _, g := range sm[1:] {
				if len(g) > 0 {
					*f = html.UnescapeString(string(g))
					break
				}
			}
		}
	}
}

// streamRe finds a stream's dictionary end and body start.
var streamRe = regexp.MustCompile(`stream\r?\n`)

// inflatedStreams returns the FlateDecode streams of a PDF, inflated, within
// the bounds above. A stream that fails to inflate is skipped.
func inflatedStreams(data []byte) [][]byte {
	var out [][]byte
	total := 0
	for _, loc := range streamRe.FindAllIndex(data, maxPDFStreams*4) {
		if len(out) >= maxPDFStreams || total >= maxPDFTotalInflate {
			break
		}
		// "endstream" also matches; a stream keyword follows a dictionary's ">>"
		if loc[0] >= 3 && string(data[loc[0]-3:loc[0]]) == "end" {
			continue
		}

		dictStart := bytes.LastIndex(data[max(0, loc[0]-2048):loc[0]], []byte("<<"))
		if dictStart < 0 || !bytes.Contains(data[max(0, loc[0]-2048)+dictStart:loc[0]], []byte("/FlateDecode")) {
			continue
		}

		body := data[loc[1]:]
		if end := bytes.Index(body, []byte("endstream")); end >= 0 {
			body = body[:end]
		}
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			continue
		}
		inflated, err := io.ReadAll(io.LimitReader(zr, maxPDFStreamInflate))
		_ = zr.Close()
		if len(inflated) == 0 || (err != nil && !errors.Is(err, io.ErrUnexpectedEOF)) {
			continue
		}

		total += len(inflated)
		out = append(out, inflated)
	}

	return out
}
