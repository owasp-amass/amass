// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"regexp"
	"strings"
)

// Content is what a document says: its body text, and the link targets it
// carries outside its text (PDF link annotations, OOXML external
// relationships), which often hold URLs the text does not show.
type Content struct {
	Text  string   `json:"text,omitempty"`
	Links []string `json:"links,omitempty"`
}

// maxText caps the text read from one document, and maxLinks its links.
const (
	maxText  = 4 << 20
	maxLinks = 2000
)

// ExtractContent reads a document's body text and link targets, offline and
// within bounds. PDF text is read from the text-showing operators of its
// content streams; a PDF whose fonts use custom encodings may give partial
// or garbled text, which the deterministic extractors downstream simply
// find nothing in. OOXML text is read from the document, header, footer,
// note and comment parts, a workbook's shared strings and sheets, and a
// presentation's slides and notes.
func ExtractContent(format string, data []byte) (Content, error) {
	switch format {
	case FormatPDF:
		return pdfContent(data)
	case FormatOOXML:
		return ooxmlContent(data)
	}
	return Content{}, ErrFormat
}

// textBuilder collects text up to maxText.
type textBuilder struct {
	b strings.Builder
}

func (t *textBuilder) write(s string) {
	if room := maxText - t.b.Len(); room > 0 {
		if len(s) > room {
			s = s[:room]
		}
		t.b.WriteString(s)
	}
}

func (t *textBuilder) full() bool { return t.b.Len() >= maxText }

// linkSet collects unique links up to maxLinks.
type linkSet struct {
	seen  map[string]bool
	links []string
}

func (l *linkSet) add(s string) {
	s = strings.TrimSpace(s)
	if s == "" || len(l.links) >= maxLinks {
		return
	}
	if l.seen == nil {
		l.seen = map[string]bool{}
	}
	if !l.seen[s] {
		l.seen[s] = true
		l.links = append(l.links, s)
	}
}

// ooxmlTextPart matches the package parts that hold a document's text.
var ooxmlTextPart = regexp.MustCompile(`^(?:word/(?:document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml|` +
	`xl/sharedStrings\.xml|xl/worksheets/sheet\d+\.xml|` +
	`ppt/slides/slide\d+\.xml|ppt/notesSlides/notesSlide\d+\.xml)$`)

// ooxmlRelsPart matches the relationship parts of the text parts.
var ooxmlRelsPart = regexp.MustCompile(`^(?:word|xl|ppt)/(?:.*/)?_rels/[^/]+\.rels$`)

// maxOOXMLContentPart caps one text part read from a package.
const maxOOXMLContentPart = 8 << 20

func ooxmlContent(data []byte) (Content, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Content{}, errNotOOXML
	}

	var text textBuilder
	var links linkSet
	for _, f := range zr.File {
		isText, isRels := ooxmlTextPart.MatchString(f.Name), ooxmlRelsPart.MatchString(f.Name)
		if !isText && !isRels {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		part, err := io.ReadAll(io.LimitReader(rc, maxOOXMLContentPart))
		_ = rc.Close()
		if err != nil {
			continue
		}

		if isRels {
			externalTargets(part, &links)
			continue
		}
		if !text.full() {
			xmlText(part, &text)
		}
	}

	return Content{Text: text.b.String(), Links: links.links}, nil
}

// xmlBreaks are the elements whose end separates text: paragraphs, table
// cells and rows, shared strings and sheet cells, breaks and tabs. Runs
// within a paragraph join without a space, since a word can be split across
// runs.
var xmlBreaks = map[string]string{"p": "\n", "tc": "\t", "tr": "\n", "si": "\n", "c": "\t", "row": "\n",
	"br": "\n", "tab": "\t", "cr": "\n"}

func xmlText(part []byte, text *textBuilder) {
	dec := xml.NewDecoder(bytes.NewReader(part))
	dec.Strict = false
	for !text.full() {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.CharData:
			text.write(string(t))
		case xml.EndElement:
			if sep, ok := xmlBreaks[t.Name.Local]; ok {
				text.write(sep)
			}
		}
	}
	text.write("\n")
}

// externalTargets adds the targets of a relationship part's external
// relationships (hyperlinks, linked files).
func externalTargets(part []byte, links *linkSet) {
	var rels struct {
		Rels []struct {
			Target     string `xml:"Target,attr"`
			TargetMode string `xml:"TargetMode,attr"`
		} `xml:"Relationship"`
	}
	if xml.Unmarshal(part, &rels) != nil {
		return
	}
	for _, r := range rels.Rels {
		if strings.EqualFold(r.TargetMode, "External") {
			links.add(r.Target)
		}
	}
}

// uriKey finds a link annotation's URI action, "/URI (…)" or "/URI <…>".
var uriKey = regexp.MustCompile(`/URI\s*[(<]`)

func pdfContent(data []byte) (Content, error) {
	if !bytes.HasPrefix(bytes.TrimLeft(data[:min(len(data), 1024)], "\x00\r\n\t "), []byte("%PDF-")) {
		return Content{}, errNotPDF
	}

	var text textBuilder
	var links linkSet
	chunks := append([][]byte{data}, inflatedStreams(data)...)
	for _, c := range chunks {
		for _, loc := range uriKey.FindAllIndex(c, maxLinks) {
			if s, ok := pdfStringAt(c, loc[1]-1); ok {
				links.add(s)
			}
		}
		if !text.full() {
			pdfText(c, &text)
		}
	}

	return Content{Text: text.b.String(), Links: links.links}, nil
}

// pdfText reads the strings shown inside the text objects (BT … ET) of a
// content stream: the literal strings of Tj, ', " and TJ. In a TJ array a
// large negative adjustment is a word space; a new text object or a line
// move starts a new line.
func pdfText(c []byte, text *textBuilder) {
	for i := 0; i < len(c) && !text.full(); {
		bt := bytes.Index(c[i:], []byte("BT"))
		if bt < 0 {
			return
		}
		start := i + bt + 2
		et := bytes.Index(c[start:], []byte("ET"))
		if et < 0 {
			et = len(c) - start
		}
		if obj := c[start : start+et]; isTextObject(obj) {
			pdfTextObject(obj, text)
			text.write("\n")
		}
		i = start + et + 2
	}
}

// maxTextObject is the longest text object read; image and font data that
// happen to hold "BT" and "ET" are usually far longer.
const maxTextObject = 64 << 10

// textShowing finds a text-showing operator: Tj, TJ, ' or " after a string
// or array.
var textShowing = regexp.MustCompile(`[)\]>]\s*(?:Tj|TJ|'|")`)

// isTextObject reports whether the bytes between a BT and an ET are a real
// text object: short, almost all printable, and showing text. Compressed
// image and font data can hold "BT" and "ET" by chance, and read as text it
// is noise in which link and name patterns match.
func isTextObject(obj []byte) bool {
	if len(obj) == 0 || len(obj) > maxTextObject || !textShowing.Match(obj) {
		return false
	}

	printable := 0
	for _, b := range obj {
		if (b >= 0x20 && b < 0x7f) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}
	return printable*100 >= len(obj)*95
}

func pdfTextObject(obj []byte, text *textBuilder) {
	var num []byte
	// gap writes a space when the number just read is a TJ adjustment of a
	// hundred thousandths of an em or more, negative: a gap about as wide as
	// a word space
	gap := func() {
		if len(num) >= 4 && num[0] == '-' {
			text.write(" ")
		}
		num = num[:0]
	}

	for i := 0; i < len(obj) && !text.full(); i++ {
		switch b := obj[i]; {
		case b == '(':
			gap()
			s, n, _ := literalSpan(obj[i+1:], maxText)
			text.write(decodePDFText(s))
			i += n
		case b == '-' || b == '.' || (b >= '0' && b <= '9'):
			num = append(num, b)
		case b == 'T' && i+1 < len(obj) && strings.IndexByte("dD*", obj[i+1]) >= 0:
			// Td, TD, T*: a line move
			num = num[:0]
			text.write("\n")
			i++
		case b == '\'' || b == '"':
			num = num[:0]
			text.write("\n")
		default:
			gap()
		}
	}
}
