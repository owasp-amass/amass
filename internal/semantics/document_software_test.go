// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

// Creator and producer values as documents write them name the product and
// the version they state.
func TestMatchDocumentSoftware(t *testing.T) {
	cases := []struct {
		value, cpe, version string
	}{
		{"Microsoft® Word for Microsoft 365", "cpe:2.3:a:microsoft:word", ""},
		{"Microsoft® Word 2016", "cpe:2.3:a:microsoft:word", "2016"},
		{"Microsoft Office Word 12.0000", "cpe:2.3:a:microsoft:word", "12.0000"},
		{"Microsoft Macintosh Excel", "cpe:2.3:a:microsoft:excel", ""},
		{"Microsoft Office PowerPoint", "cpe:2.3:a:microsoft:powerpoint", ""},
		{"Acrobat Distiller 10.1.8 (Windows)", "cpe:2.3:a:adobe:acrobat", "10.1.8"},
		{"Adobe Acrobat Pro DC 21.1.20135", "cpe:2.3:a:adobe:acrobat", "21.1.20135"},
		{"Adobe InDesign 18.5 (Macintosh)", "cpe:2.3:a:adobe:indesign", "18.5"},
		{"Adobe InDesign CC 2017 (Macintosh)", "cpe:2.3:a:adobe:indesign", "2017"},
		{"Adobe Photoshop 24.0 (Windows)", "cpe:2.3:a:adobe:photoshop", "24.0"},
		{"LibreOffice 7.3", "cpe:2.3:a:libreoffice:libreoffice", "7.3"},
		{"LibreOffice/7.3.7.2$Linux_X86_64 LibreOffice_project/30$Build-2", "cpe:2.3:a:libreoffice:libreoffice", "7.3.7.2"},
		{"OpenOffice.org 3.2", "cpe:2.3:a:apache:openoffice", "3.2"},
		{"macOS Version 13.4 (Build 22F66) Quartz PDFContext", "cpe:2.3:o:apple:macos", "13.4"},
		{"Mac OS X 10.11.6 Quartz PDFContext", "cpe:2.3:o:apple:mac_os_x", "10.11.6"},
		{"iText® 5.5.13 ©2000-2020 iText Group NV (AGPL-version)", "cpe:2.3:a:itextpdf:itext", "5.5.13"},
		{"GPL Ghostscript 9.53.3", "cpe:2.3:a:artifex:ghostscript", "9.53.3"},
	}
	for _, c := range cases {
		p, v, ok := MatchDocumentSoftware(c.value)
		if !ok || p.CPE != c.cpe || v != c.version {
			t.Errorf("%q = %q %q %v, want %q %q", c.value, p.CPE, v, ok, c.cpe, c.version)
		}
	}

	for _, v := range []string{"", "Skia/PDF m118", "Wordsmith 2.0", "Acme PDF 2.1"} {
		if p, _, ok := MatchDocumentSoftware(v); ok {
			t.Errorf("%q matched %s", v, p.CPE)
		}
	}
}

func TestReleaseName(t *testing.T) {
	p, v, _ := MatchDocumentSoftware("Microsoft® Word 2016")
	if got := p.ReleaseName(v); got != "Microsoft Word 2016" {
		t.Errorf("release %q", got)
	}
	if p.ReleaseName("") != "" {
		t.Error("no version, no release")
	}
}
