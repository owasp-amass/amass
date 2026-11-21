// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"
	"sync"
)

// DocumentType is one document format the document collector reads.
type DocumentType struct {
	Ext       string `json:"ext"`
	MediaType string `json:"media_type"`
	Format    string `json:"format"`
}

// DocumentRules say which documents the document collector reads and how
// much it downloads. Loaded from documents.json; see that file's _about.
type DocumentRules struct {
	License  string `json:"_license"`
	About    string `json:"_about"`
	MaxBytes int64  `json:"max_bytes"`
	// PlaceholderAuthors are author values written by default, naming no one.
	PlaceholderAuthors []string `json:"placeholder_authors"`
	// PlaceholderCompanies are Company values preset by a computer's maker or
	// left by default, naming no author's organization.
	PlaceholderCompanies []string       `json:"placeholder_companies"`
	Types                []DocumentType `json:"types"`
	Sources              []string       `json:"sources"`
	byExt                map[string]DocumentType
	placeholders         map[string]bool
	companies            map[string]bool
}

// documentFormats are the formats that have an extractor (internal/docmeta).
var documentFormats = map[string]bool{"pdf": true, "ooxml": true}

var loadDocumentRules = sync.OnceValue(func() DocumentRules {
	var r DocumentRules
	dec := json.NewDecoder(bytes.NewReader(File("documents.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		panic("documents.json: " + err.Error())
	}
	if r.MaxBytes <= 0 || len(r.Types) == 0 || len(r.Sources) == 0 {
		panic("documents.json: max_bytes, types and sources are required")
	}

	r.byExt = make(map[string]DocumentType, len(r.Types))
	for _, t := range r.Types {
		ext := strings.ToLower(t.Ext)
		if !strings.HasPrefix(ext, ".") || t.MediaType == "" || !documentFormats[t.Format] {
			panic("documents.json: type " + t.Ext + " needs a dotted ext, a media_type and a known format")
		}
		r.byExt[ext] = t
	}
	r.placeholders = make(map[string]bool, len(r.PlaceholderAuthors))
	for _, a := range r.PlaceholderAuthors {
		r.placeholders[strings.ToLower(strings.TrimSpace(a))] = true
	}
	r.companies = make(map[string]bool, len(r.PlaceholderCompanies))
	for _, c := range r.PlaceholderCompanies {
		r.companies[strings.ToLower(strings.TrimSpace(c))] = true
	}
	for _, s := range r.Sources {
		if !strings.HasPrefix(s, "https://") {
			panic("documents.json: sources must be https URLs")
		}
	}

	return r
})

// Documents returns the document rules.
func Documents() DocumentRules { return loadDocumentRules() }

// DocumentFor returns the document type a URL path names, by its extension.
func (r DocumentRules) DocumentFor(p string) (DocumentType, bool) {
	t, ok := r.byExt[strings.ToLower(path.Ext(p))]
	return t, ok
}

// IsPlaceholderAuthor reports whether an author value is one office software
// writes by default ("Microsoft Office User"), which names no person.
func (r DocumentRules) IsPlaceholderAuthor(author string) bool {
	return r.placeholders[strings.ToLower(strings.TrimSpace(author))]
}

// IsPlaceholderCompany reports whether a Company value is one a computer's
// maker presets or one left by default ("Dell Inc.", "Home").
func (r DocumentRules) IsPlaceholderCompany(company string) bool {
	return r.companies[strings.ToLower(strings.TrimSpace(company))]
}
