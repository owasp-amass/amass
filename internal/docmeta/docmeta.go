// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package docmeta reads the metadata documents carry — who wrote them, with
// what software, when, and for which company — from PDF and Office (OOXML)
// files, offline and with the standard library only. It parses no content
// beyond the metadata, never executes anything in a document, and bounds the
// work it does on hostile input. The document collector (Unit 11) stores what
// it returns as observations on a File asset.
package docmeta

import (
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Metadata is what a document says about itself. Every field is as the
// document states it; none is verified.
type Metadata struct {
	Title          string `json:"title,omitempty"`
	Author         string `json:"author,omitempty"`
	LastModifiedBy string `json:"last_modified_by,omitempty"`
	// Creator is the software that created the content (PDF /Creator,
	// xmp:CreatorTool, OOXML Application); Producer the software that wrote
	// the PDF.
	Creator  string `json:"creator,omitempty"`
	Producer string `json:"producer,omitempty"`
	Company  string `json:"company,omitempty"`
	// Created and Modified are RFC 3339 when the document's date parses,
	// otherwise as written.
	Created  string `json:"created,omitempty"`
	Modified string `json:"modified,omitempty"`
	// Usernames are account names read from file-system paths in the
	// metadata (C:\Users\<name>\…, /Users/<name>/…, /home/<name>/…).
	Usernames []string `json:"usernames,omitempty"`
}

// Empty reports whether the document stated nothing.
func (m Metadata) Empty() bool {
	return m.Title == "" && m.Author == "" && m.LastModifiedBy == "" && m.Creator == "" &&
		m.Producer == "" && m.Company == "" && m.Created == "" && m.Modified == "" && len(m.Usernames) == 0
}

// Formats the extractors read, as named in internal/semantics/documents.json.
const (
	FormatPDF   = "pdf"
	FormatOOXML = "ooxml"
)

// ErrFormat is returned for a format with no extractor.
var ErrFormat = errors.New("docmeta: unsupported format")

// Extract reads the metadata of a document of the given format.
func Extract(format string, data []byte) (Metadata, error) {
	var m Metadata
	var err error
	switch format {
	case FormatPDF:
		m, err = extractPDF(data)
	case FormatOOXML:
		m, err = extractOOXML(data)
	default:
		return m, ErrFormat
	}
	if err != nil {
		return m, err
	}

	m.normalize()
	return m, nil
}

// normalize trims the fields and reads usernames out of the paths in them.
func (m *Metadata) normalize() {
	for _, f := range []*string{&m.Title, &m.Author, &m.LastModifiedBy, &m.Creator, &m.Producer, &m.Company,
		&m.Created, &m.Modified} {
		*f = clean(*f)
	}

	seen := map[string]bool{}
	for _, u := range m.Usernames {
		seen[strings.ToLower(u)] = true
	}
	for _, v := range []string{m.Title, m.Author, m.LastModifiedBy, m.Creator, m.Producer, m.Company} {
		for _, match := range userPathRe.FindAllStringSubmatch(v, -1) {
			name := match[1]
			if name == "" || ignoredUser[strings.ToLower(name)] || seen[strings.ToLower(name)] {
				continue
			}
			seen[strings.ToLower(name)] = true
			m.Usernames = append(m.Usernames, name)
		}
	}
	sort.Strings(m.Usernames)
	m.Usernames = slices.Compact(m.Usernames)
}

// userPathRe captures the account name in a home-directory path.
var userPathRe = regexp.MustCompile(
	`(?i)(?:[a-z]:\\(?:users|documents and settings)\\|/users/|/home/)([^\\/:*?"<>|\s]{1,64})`)

// ignoredUser are home-directory names that name no person.
var ignoredUser = map[string]bool{"public": true, "default": true, "all users": true, "administrator": true,
	"shared": true, "guest": true}

// clean trims space and control characters and caps the length, so a
// hostile document cannot fill a property.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxField {
		s = s[:maxField]
	}
	return s
}

// maxField caps a metadata value.
const maxField = 512

// normalizeDate turns a document date into RFC 3339 when it parses, or
// returns it as written.
func normalizeDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if t, ok := parsePDFDate(s); ok {
		return t.UTC().Format(time.RFC3339)
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

// pdfDateRe matches a PDF date: D:YYYYMMDDHHmmSS followed by an optional
// offset (Z, or +HH'mm').
var pdfDateRe = regexp.MustCompile(`^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(Z|[+-]\d{2}'?\d{2}'?)?`)

func parsePDFDate(s string) (time.Time, bool) {
	m := pdfDateRe.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, false
	}

	part := func(i int, def string) string {
		if m[i] == "" {
			return def
		}
		return m[i]
	}
	zone := "Z"
	if z := m[7]; z != "" && z != "Z" {
		z = strings.ReplaceAll(z, "'", "")
		zone = z[:3] + ":" + z[3:]
	}

	t, err := time.Parse(time.RFC3339, part(1, "")+"-"+part(2, "01")+"-"+part(3, "01")+"T"+part(4, "00")+":"+
		part(5, "00")+":"+part(6, "00")+zone)
	return t, err == nil
}
