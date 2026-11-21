// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensDocuments asks for the documents a domain or organization publishes:
// the Files the document collector stored from its URLs, who and what made
// them, the accounts they show and what they mention. Built in Go from stored
// assets; nothing is written and nothing is fetched.
const LensDocuments = "documents"

// documentsShown bounds the documents listed in a report.
const documentsShown = 50

var documentsLens = SubjectLens{
	Name:    LensDocuments,
	Command: "documents",
	Description: "List the documents a domain or organization publishes (PDF, Office): who wrote them, the " +
		"software that made them, the user accounts and the names, addresses and contacts they reveal. Read-only",
	Examples: []string{"What documents does <domain> publish?",
		"Which usernames or authors do <organization>'s documents reveal?",
		"What software made <domain>'s PDFs?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindDocuments(ctx, g, schema, root, opts.Limits)
	},
}

// The document properties the collector writes (engine/plugins/documents).
const (
	propDocTitle         = "doc_title"
	propDocCreated       = "doc_created"
	propDocModified      = "doc_modified"
	propDocRetrievedFrom = "doc_retrieved_from"
)

// Document is one stored File the subject publishes.
type Document struct {
	URL      string `json:"url"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Title    string `json:"title,omitempty"`
	Created  string `json:"created,omitempty"`
	Modified string `json:"modified,omitempty"`
	// Archived marks a document read from a web archive's copy rather than
	// from its own URL.
	Archived bool `json:"archived,omitempty"`
	// Authors are the people and organizations its metadata names; Software
	// the products or releases that made it; Accounts the directory accounts
	// it shows.
	Authors  []string `json:"authors,omitempty"`
	Software []string `json:"software,omitempty"`
	Accounts []string `json:"accounts,omitempty"`
	// Mentions counts what its content names, by asset type; Emails and
	// Names list the email addresses and host names among them.
	Mentions map[string]int `json:"mentions,omitempty"`
	Emails   []string       `json:"emails,omitempty"`
	Names    []string       `json:"names,omitempty"`
	// Copies are the other URLs serving the same bytes (the same content
	// hash).
	Copies []string `json:"copies,omitempty"`
}

// DocumentsReport is the result of the documents lens.
type DocumentsReport struct {
	lensBase
	Documents []Document `json:"documents"`
	Total     int        `json:"total"`
	// ByType counts the documents by media type.
	ByType map[string]int `json:"by_type,omitempty"`
	// Authors, Software and Accounts are the distinct values across all the
	// documents, with how many documents name each.
	Authors  map[string]int `json:"authors,omitempty"`
	Software map[string]int `json:"software,omitempty"`
	Accounts map[string]int `json:"accounts,omitempty"`
	Archived int            `json:"archived,omitempty"`
}

// FindDocuments lists the documents stored from the URLs a domain or
// organization controls. It reads only.
func FindDocuments(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (DocumentsReport, error) {
	g = graph.Cached(g)
	out := DocumentsReport{ByType: map[string]int{}, Authors: map[string]int{}, Software: map[string]int{},
		Accounts: map[string]int{}}
	s, err := newScope(ctx, g, schema, root, limits, LensDocuments)
	if err != nil {
		return out, err
	}

	urls, err := s.ownedURLs()
	if err != nil {
		return out, err
	}

	seen := map[string]bool{}
	byHash := map[string][]string{}
	var docs []Document
	var hashes []string
	for _, u := range urls {
		if s.spent() {
			break
		}
		steps, err := s.w.steps(u)
		if err != nil {
			return out, err
		}
		for _, st := range steps {
			if !st.forward || st.other.Type != "File" || seen[st.other.ID] {
				continue
			}
			seen[st.other.ID] = true

			doc, hash, err := s.document(st.other)
			if err != nil {
				return out, err
			}
			docs = append(docs, doc)
			hashes = append(hashes, hash)
			if hash != "" {
				byHash[hash] = append(byHash[hash], doc.URL)
			}
		}
	}

	for i := range docs {
		d := &docs[i]
		for _, other := range byHash[hashes[i]] {
			if other != d.URL {
				graph.AddUnique(&d.Copies, other)
			}
		}
		out.Total++
		if d.Type != "" {
			out.ByType[d.Type]++
		}
		if d.Archived {
			out.Archived++
		}
		for _, a := range d.Authors {
			out.Authors[a]++
		}
		for _, sw := range d.Software {
			out.Software[sw]++
		}
		for _, a := range d.Accounts {
			out.Accounts[a]++
		}
	}

	// documents that reveal the most come first
	sort.SliceStable(docs, func(i, j int) bool {
		ri, rj := docs[i].revealing(), docs[j].revealing()
		if ri != rj {
			return ri > rj
		}
		return docs[i].URL < docs[j].URL
	})
	if len(docs) > documentsShown {
		docs = docs[:documentsShown]
	}
	out.Documents = docs
	out.lensBase = s.base()
	return out, nil
}

// revealing scores how much a document gives away: accounts and authors
// first, then emails and other mentions.
func (d Document) revealing() int {
	n := 0
	for _, c := range d.Mentions {
		n += c
	}
	return 100*len(d.Accounts) + 50*len(d.Authors) + 10*len(d.Emails) + n
}

// document reads one stored File: its content, properties and the assets it
// is linked to. It returns the File's content hash, when stored, so copies
// of the same bytes can be grouped.
func (s *scope) document(f graph.Asset) (Document, string, error) {
	d := Document{
		URL:      graph.ContentString(f, "url"),
		Name:     graph.ContentString(f, "name"),
		Type:     graph.ContentString(f, "type"),
		Size:     int64(contentFloat(f, "size")),
		Mentions: map[string]int{},
	}
	if d.URL == "" {
		d.URL = graph.AssetLabel(f)
	}

	if ev, err := s.w.graph.Evidence(s.w.ctx, f.ID, 100); err == nil {
		d.Title = firstValue(propertyValues(ev, propDocTitle))
		d.Created = firstValue(propertyValues(ev, propDocCreated))
		d.Modified = firstValue(propertyValues(ev, propDocModified))
		if from := firstValue(propertyValues(ev, propDocRetrievedFrom)); from != "" && from != d.URL {
			d.Archived = true
		}
	}

	steps, err := s.w.steps(f)
	if err != nil {
		return d, "", err
	}

	var hash string
	for _, st := range steps {
		if !st.forward {
			continue
		}
		label := graph.AssetLabel(st.other)
		switch st.edge.Label {
		case "author":
			graph.AddUnique(&d.Authors, label)
		case "created_with":
			name := graph.ContentString(st.other, "product_name", "name")
			if name == "" {
				name = label
			}
			graph.AddUnique(&d.Software, name)
		case "fingerprint":
			if graph.ContentString(st.other, "id_type") == "file_sha256" {
				hash = graph.ContentString(st.other, "id")
			}
		case "contains":
			switch st.other.Type {
			case "Account":
				user := graph.ContentString(st.other, "username")
				if user == "" {
					user = label
				}
				graph.AddUnique(&d.Accounts, user)
			case "Identifier":
				if graph.ContentString(st.other, "id_type") == "email" {
					graph.AddUnique(&d.Emails, graph.ContentString(st.other, "id"))
				}
				d.Mentions[st.other.Type]++
			case "FQDN":
				if s.ownDomains[graph.RegisteredDomain(label)] {
					graph.AddUnique(&d.Names, label)
				}
				d.Mentions[st.other.Type]++
			default:
				d.Mentions[st.other.Type]++
			}
		}
	}

	for _, l := range [][]string{d.Authors, d.Software, d.Accounts, d.Emails, d.Names} {
		sort.Strings(l)
	}
	if len(d.Mentions) == 0 {
		d.Mentions = nil
	}
	return d, hash, nil
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	sort.Strings(values)
	return values[0]
}

// Text renders the report.
func (r DocumentsReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Documents published by %s: %d stored", subject, r.Total)
	if r.Archived > 0 {
		fmt.Fprintf(&b, " (%d read from a web archive's copy)", r.Archived)
	}
	fmt.Fprintf(&b, " (%d reads).\n", r.Reads)
	if r.Total == 0 {
		b.WriteString("\nNo document is stored for the subject's URLs. The document collector stores PDF and " +
			"Office files it finds through any source.\n")
		return b.String()
	}

	writeCounts(&b, "By type", r.ByType)
	writeCounts(&b, "Authors named in metadata", r.Authors)
	writeCounts(&b, "Software that made them", r.Software)
	writeCounts(&b, "User accounts the documents reveal", r.Accounts)

	b.WriteString("\nDocuments (most revealing first):\n")
	for _, d := range r.Documents {
		fmt.Fprintf(&b, "  %s", d.URL)
		var facts []string
		if d.Type != "" {
			facts = append(facts, d.Type)
		}
		if d.Size > 0 {
			facts = append(facts, fmt.Sprintf("%d bytes", d.Size))
		}
		if d.Archived {
			facts = append(facts, "archive copy")
		}
		if len(facts) > 0 {
			fmt.Fprintf(&b, " (%s)", strings.Join(facts, ", "))
		}
		b.WriteString("\n")
		if d.Title != "" {
			fmt.Fprintf(&b, "    title: %s\n", d.Title)
		}
		if d.Created != "" || d.Modified != "" {
			fmt.Fprintf(&b, "    created %s, modified %s\n", orDash(d.Created), orDash(d.Modified))
		}
		writeDocList(&b, "authors", d.Authors)
		writeDocList(&b, "made with", d.Software)
		writeDocList(&b, "accounts", d.Accounts)
		writeDocList(&b, "emails", d.Emails)
		writeDocList(&b, "own names", d.Names)
		if len(d.Mentions) > 0 {
			keys := make([]string, 0, len(d.Mentions))
			for k := range d.Mentions {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%d %s", d.Mentions[k], k))
			}
			fmt.Fprintf(&b, "    mentions: %s\n", strings.Join(parts, ", "))
		}
		writeDocList(&b, "same file at", d.Copies)
	}
	if r.Total > len(r.Documents) {
		fmt.Fprintf(&b, "  and %d more\n", r.Total-len(r.Documents))
	}

	b.WriteString("\nThese are documents stored by past enumerations, with what their metadata and content " +
		"state; nothing was fetched for this report." + r.partialNote() + "\n")
	return b.String()
}

func writeCounts(b *strings.Builder, title string, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	fmt.Fprintf(b, "\n%s:\n", title)
	for _, k := range keys {
		fmt.Fprintf(b, "  %s: %d\n", k, counts[k])
	}
}

func writeDocList(b *strings.Builder, label string, values []string) {
	if len(values) > 0 {
		fmt.Fprintf(b, "    %s: %s\n", label, strings.Join(values, ", "))
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Facts names what the report found.
func (r DocumentsReport) Facts() []string {
	out := make([]string, 0, len(r.Documents)+len(r.Accounts))
	for _, d := range r.Documents {
		out = append(out, "document "+d.URL)
	}
	for a := range r.Accounts {
		out = append(out, "account "+a)
	}
	for a := range r.Authors {
		out = append(out, "author "+a)
	}
	sort.Strings(out)
	return out
}
