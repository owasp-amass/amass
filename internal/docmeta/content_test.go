// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package docmeta

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"
)

// The text of a PDF's text objects is read, TJ gaps become spaces, and link
// annotations' URIs are listed, from the raw file and from compressed
// streams.
func TestPDFContent(t *testing.T) {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	_, _ = zw.Write([]byte("BT /F1 12 Tf 72 700 Td (Contact the help desk at helpdesk@example.edu) Tj " +
		"0 -14 Td [(VPN:)-250(vpn.example.edu)] TJ ET"))
	_ = zw.Close()

	pdf := fmt.Sprintf("%%PDF-1.7\n1 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI "+
		"/URI (https://portal.example.edu/login) >> >>\nendobj\n2 0 obj\n<< /Length %d /Filter /FlateDecode >>\n"+
		"stream\n%s\nendstream\nendobj\n%%%%EOF\n", z.Len(), z.String())

	c, err := ExtractContent(FormatPDF, []byte(pdf))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"helpdesk@example.edu", "VPN: vpn.example.edu"} {
		if !strings.Contains(c.Text, want) {
			t.Errorf("text %q lacks %q", c.Text, want)
		}
	}
	if len(c.Links) != 1 || c.Links[0] != "https://portal.example.edu/login" {
		t.Errorf("links %v", c.Links)
	}
}

// An OOXML package's text parts are read with paragraph breaks, runs join
// within a paragraph, and external relationship targets are listed; other
// parts are not read.
func TestOOXMLContent(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string) {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	add("word/document.xml", `<w:document xmlns:w="w"><w:body>`+
		`<w:p><w:r><w:t>Server: intra</w:t></w:r><w:r><w:t>net.example.edu</w:t></w:r></w:p>`+
		`<w:p><w:r><w:t>Call 315-555-0100</w:t></w:r></w:p></w:body></w:document>`)
	add("word/_rels/document.xml.rels", `<Relationships>`+
		`<Relationship Id="r1" Type="hyperlink" Target="https://wiki.example.edu/it" TargetMode="External"/>`+
		`<Relationship Id="r2" Type="styles" Target="styles.xml"/></Relationships>`)
	add("word/styles.xml", `<w:styles>NOT TEXT</w:styles>`)
	_ = zw.Close()

	c, err := ExtractContent(FormatOOXML, buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Text, "Server: intranet.example.edu\n") || !strings.Contains(c.Text, "Call 315-555-0100") {
		t.Errorf("text %q", c.Text)
	}
	if strings.Contains(c.Text, "NOT TEXT") {
		t.Error("a non-text part was read")
	}
	if len(c.Links) != 1 || c.Links[0] != "https://wiki.example.edu/it" {
		t.Errorf("links %v", c.Links)
	}
}

func TestContentRejectsOtherData(t *testing.T) {
	if _, err := ExtractContent(FormatPDF, []byte("<html>")); err == nil {
		t.Error("HTML read as PDF")
	}
	if _, err := ExtractContent(FormatOOXML, []byte("%PDF-1.4")); err == nil {
		t.Error("PDF read as OOXML")
	}
	if _, err := ExtractContent("doc", nil); err != ErrFormat {
		t.Errorf("unknown format err = %v", err)
	}
}
