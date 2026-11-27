// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf16"
)

// A plain Info dictionary: escapes, nested parentheses and octal codes are
// decoded, a bookmark's /Title is not taken for the document's, dates become
// RFC 3339, and a home-directory path yields the account name.
func TestPDFInfoDictionary(t *testing.T) {
	pdf := "%PDF-1.4\n" +
		"3 0 obj << /Title (Chapter 1) /Parent 2 0 R >> endobj\n" +
		"9 0 obj << /Title (Budget \\(FY26\\) draft) /Author (Jane Doe) " +
		"/Creator (C:\\\\Users\\\\jdoe\\\\Desktop\\\\budget.docx) /Producer (Microsoft\\256 Word 2016) " +
		"/CreationDate (D:20240304050607-05'00') /ModDate (D:20240310) >> endobj\n" +
		"trailer << /Info 9 0 R >>\n%%EOF\n"

	m, err := Extract(FormatPDF, []byte(pdf))
	if err != nil {
		t.Fatal(err)
	}

	want := Metadata{
		Title:     "Budget (FY26) draft",
		Author:    "Jane Doe",
		Creator:   `C:\Users\jdoe\Desktop\budget.docx`,
		Producer:  "Microsoft® Word 2016",
		Created:   "2024-03-04T10:06:07Z",
		Modified:  "2024-03-10T00:00:00Z",
		Usernames: []string{"jdoe"},
	}
	if !equal(m, want) {
		t.Errorf("metadata = %+v\nwant       %+v", m, want)
	}
}

// Modern PDFs keep the Info dictionary in a compressed object stream; a
// UTF-16 hex string is decoded.
func TestPDFCompressedInfoAndUTF16(t *testing.T) {
	author := utf16Hex("Zoë Smith")
	dict := "<< /Author <" + author + "> /Producer (pdfTeX-1.40.25) /CreationDate (D:20230102030405Z) >>"

	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write([]byte("12 0 " + dict))
	_ = zw.Close()

	pdf := "%PDF-1.7\n5 0 obj << /Type /ObjStm /N 1 /First 5 /Filter /FlateDecode /Length " +
		"99 >>\nstream\n" + z.String() + "\nendstream\nendobj\n%%EOF\n"

	m, err := Extract(FormatPDF, []byte(pdf))
	if err != nil {
		t.Fatal(err)
	}
	if m.Author != "Zoë Smith" || m.Producer != "pdfTeX-1.40.25" || m.Created != "2023-01-02T03:04:05Z" {
		t.Errorf("metadata = %+v", m)
	}
}

// Without an Info author, the XMP packet's dc:creator and tool are read.
func TestPDFXMPFallback(t *testing.T) {
	pdf := `%PDF-1.6
1 0 obj << /Type /Metadata /Subtype /XML >> stream
<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description
 xmp:CreatorTool="Adobe InDesign 18.0" xmp:CreateDate="2022-05-06T07:08:09-04:00">
<dc:creator><rdf:Seq><rdf:li>Marketing &amp; Communications</rdf:li></rdf:Seq></dc:creator>
<pdf:Producer>Adobe PDF Library 17.0</pdf:Producer>
</rdf:Description></rdf:RDF></x:xmpmeta>
endstream endobj
%%EOF
`
	m, err := Extract(FormatPDF, []byte(pdf))
	if err != nil {
		t.Fatal(err)
	}
	if m.Author != "Marketing & Communications" || m.Creator != "Adobe InDesign 18.0" ||
		m.Producer != "Adobe PDF Library 17.0" || m.Created != "2022-05-06T11:08:09Z" {
		t.Errorf("metadata = %+v", m)
	}
}

func TestOOXMLProperties(t *testing.T) {
	core := `<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">
<dc:title>Enrollment Report</dc:title><dc:creator>Registrar Office</dc:creator>
<cp:lastModifiedBy>bsmith</cp:lastModifiedBy>
<dcterms:created>2021-09-01T12:00:00Z</dcterms:created><dcterms:modified>2021-09-02T08:30:00Z</dcterms:modified>
</cp:coreProperties>`
	app := `<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
<Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion>
<Company>SUNY Polytechnic Institute</Company></Properties>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{"docProps/core.xml": core, "docProps/app.xml": app,
		"word/document.xml": "<w:document/>"} {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	_ = zw.Close()

	m, err := Extract(FormatOOXML, buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	want := Metadata{
		Title:          "Enrollment Report",
		Author:         "Registrar Office",
		LastModifiedBy: "bsmith",
		Creator:        "Microsoft Office Word 16.0000",
		Company:        "SUNY Polytechnic Institute",
		Created:        "2021-09-01T12:00:00Z",
		Modified:       "2021-09-02T08:30:00Z",
	}
	if !equal(m, want) {
		t.Errorf("metadata = %+v\nwant       %+v", m, want)
	}
}

func TestExtractRejectsOtherData(t *testing.T) {
	if _, err := Extract(FormatPDF, []byte("<html>not a pdf</html>")); err == nil {
		t.Error("an HTML page was read as a PDF")
	}
	if _, err := Extract(FormatOOXML, []byte("%PDF-1.4")); err == nil {
		t.Error("a PDF was read as an Office package")
	}
	if _, err := Extract("rtf", nil); err != ErrFormat {
		t.Errorf("unknown format error = %v", err)
	}
}

// A hostile document cannot fill a property: values are capped and control
// characters dropped; system home folders are not read as usernames.
func TestMetadataIsBounded(t *testing.T) {
	pdf := "%PDF-1.4\n1 0 obj << /Author (" + strings.Repeat("A", 5000) + ") /Producer (x\x01y) " +
		"/Creator (C:\\\\Users\\\\Public\\\\file.pdf) >> endobj\n"
	m, err := Extract(FormatPDF, []byte(pdf))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Author) > maxField || m.Producer != "xy" || len(m.Usernames) != 0 {
		t.Errorf("author %d bytes, producer %q, usernames %v", len(m.Author), m.Producer, m.Usernames)
	}
}

func utf16Hex(s string) string {
	b := []byte{0xFE, 0xFF}
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u>>8), byte(u))
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func equal(a, b Metadata) bool {
	return a.Title == b.Title && a.Author == b.Author && a.LastModifiedBy == b.LastModifiedBy &&
		a.Creator == b.Creator && a.Producer == b.Producer && a.Company == b.Company &&
		a.Created == b.Created && a.Modified == b.Modified &&
		strings.Join(a.Usernames, ",") == strings.Join(b.Usernames, ",")
}

// Account names are read from home-directory paths in any text; shared
// folders that name no person are skipped.
func TestUsernames(t *testing.T) {
	got := Usernames(`Saved to C:\Users\jsmith\Desktop\plan.docx, copied from /home/mdoe/share and ` +
		`C:\Users\Public\Documents; again C:\Users\JSmith\x`)
	if strings.Join(got, ",") != "jsmith,mdoe" {
		t.Errorf("usernames %v", got)
	}
}

// National phone numbers are read in the country of the document's
// country-code domain, otherwise in the US.
func TestPhoneRegion(t *testing.T) {
	for host, want := range map[string]string{"www.sunyit.edu": "US", "www.example.co.uk": "GB", "www.example.de": "DE",
		"example.de.": "DE", "example.com": "US", "": "US"} {
		if got := PhoneRegion(host); got != want {
			t.Errorf("PhoneRegion(%q) = %s, want %s", host, got, want)
		}
	}
}

// Some producers write a PDF date without its "D:" prefix; it is read the
// same, but a bare year or other short number is not taken for a date.
func TestNormalizeDateBarePDFDate(t *testing.T) {
	cases := map[string]string{
		"20091105124021":        "2009-11-05T12:40:21Z",
		"20091105":              "2009-11-05T00:00:00Z",
		"D:20091105124021":      "2009-11-05T12:40:21Z",
		"20091105124021-05'00'": "2009-11-05T17:40:21Z",
		"2009":                  "2009",
		"123":                   "123",
	}
	for in, want := range cases {
		if got := NormalizeDate(in); got != want {
			t.Errorf("NormalizeDate(%q) = %q, want %q", in, got, want)
		}
	}
}
