// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// docModel replies with each text in turn and records what it was sent.
type docModel struct {
	replies   []string
	histories [][]llm.Message
}

func (m *docModel) Generate(_ context.Context, h []llm.Message, _ []llm.ToolSpec) (llm.Response, error) {
	m.histories = append(m.histories, h)
	return llm.Response{Text: m.replies[min(len(m.histories)-1, len(m.replies)-1)]}, nil
}

var docText = strings.Join([]string{
	"The SUNY Poly Foundation is a division of SUNY Polytechnic Institute.",
	"Jane Doe, Chief Information Officer at SUNY Polytechnic Institute, oversees IT.",
	"Staff connect remotely through vpn.sunyit.edu, and the data center hosts 192.0.2.0/24.",
	"The college uses Workday for payroll. SUNY Polytechnic Institute was founded in 1966.",
}, " ")

// Findings that quote the text, use a type, relation or field the vocabulary
// allows and write their names near the quote are kept; the rest are rejected.
func TestReadDocumentValidates(t *testing.T) {
	reply := `{"category": "staff_directory",
	 "assets": [
	  {"type": "FQDN", "value": "vpn.sunyit.edu", "quote": "Staff connect remotely through vpn.sunyit.edu"},
	  {"type": "Netblock", "value": "192.0.2.0/24", "quote": "the data center hosts 192.0.2.0/24"},
	  {"type": "Product", "value": "Workday", "quote": "The college uses Workday for payroll."},
	  {"type": "FQDN", "value": "not a host", "quote": "Staff connect remotely"},
	  {"type": "Service", "value": "Payroll", "quote": "The college uses Workday for payroll."}
	 ],
	 "statements": [
	  {"subject": "SUNY Poly Foundation", "subject_type": "Organization", "predicate": "unit_of",
	   "object": "SUNY Polytechnic Institute", "object_type": "Organization",
	   "quote": "The SUNY Poly Foundation is a division of SUNY Polytechnic Institute."},
	  {"subject": "Jane Doe", "subject_type": "Person", "predicate": "holds_role",
	   "object": "SUNY Polytechnic Institute", "object_type": "Organization", "detail": "Chief Information Officer",
	   "quote": "Jane Doe, Chief Information Officer at SUNY Polytechnic Institute"},
	  {"subject": "SUNY Polytechnic Institute", "subject_type": "Organization", "predicate": "member",
	   "object": "Jane Doe", "object_type": "Person",
	   "quote": "Jane Doe, Chief Information Officer at SUNY Polytechnic Institute"},
	  {"subject": "SUNY Poly Foundation", "subject_type": "Organization", "predicate": "unit_of",
	   "object": "State University of New York", "object_type": "Organization",
	   "quote": "The SUNY Poly Foundation is a division of SUNY Polytechnic Institute."},
	  {"subject": "Jane Doe", "subject_type": "Person", "predicate": "subsidiary",
	   "object": "SUNY Polytechnic Institute", "object_type": "Organization",
	   "quote": "Jane Doe, Chief Information Officer"},
	  {"subject": "Acme", "subject_type": "Organization", "predicate": "supplied_by",
	   "object": "SUNY Polytechnic Institute", "object_type": "Organization",
	   "quote": "Acme supplies the College"}
	 ],
	 "attributes": [
	  {"subject": "SUNY Polytechnic Institute", "subject_type": "Organization", "field": "founding_date",
	   "value": "1966", "quote": "SUNY Polytechnic Institute was founded in 1966."},
	  {"subject": "SUNY Polytechnic Institute", "subject_type": "Organization", "field": "shoe_size",
	   "value": "9", "quote": "SUNY Polytechnic Institute was founded in 1966."}
	 ]}`
	model := &docModel{replies: []string{reply}}

	r, err := ReadDocument(context.Background(), model, "test-model", "https://sunyit.edu/a.pdf", docText, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Category != "staff_directory" || r.Chunks != 1 {
		t.Errorf("category %q, chunks %d", r.Category, r.Chunks)
	}

	kinds := map[string]int{}
	for _, s := range r.Statements {
		kinds[s.Kind]++
		if s.Model != "test-model" {
			t.Errorf("finding without its model: %+v", s)
		}
	}
	if kinds[FindingAsset] != 3 || kinds[FindingRelation] != 3 || kinds[FindingAttribute] != 1 {
		t.Fatalf("kept %v: %+v (rejected %q)", kinds, r.Statements, r.Rejected)
	}
	joined := strings.Join(r.Rejected, "|")
	for _, want := range []string{"is not a FQDN", "not a type documents are read for", "not written where it is quoted",
		"does not relate Person to Organization", "not in the document", "has no field"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no rejection for %q in %q", want, r.Rejected)
		}
	}
}

// A long document is read whole, chunk by chunk; the same finding from two
// chunks is kept once, and the category most chunks give wins.
func TestReadDocumentReadsEveryChunk(t *testing.T) {
	text := strings.Repeat("Filler sentence about the campus grounds. ", 200) + docText
	reply := `{"category": "policy", "assets": [{"type": "FQDN", "value": "vpn.sunyit.edu",
	  "quote": "Staff connect remotely through vpn.sunyit.edu"}], "statements": [], "attributes": []}`
	model := &docModel{replies: []string{`{"category": "other", "assets": [], "statements": [], "attributes": []}`,
		reply}}

	r, err := ReadDocument(context.Background(), model, "m", "u", text, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if r.Chunks != len(model.histories) || r.Chunks < 4 {
		t.Fatalf("read %d chunks with %d requests", r.Chunks, len(model.histories))
	}
	if !strings.Contains(model.histories[len(model.histories)-1][1].Text, "vpn.sunyit.edu") {
		t.Error("the end of the document was never read")
	}
	if len(r.Statements) != 1 {
		t.Fatalf("findings %+v", r.Statements)
	}
	if r.Category != "policy" {
		t.Errorf("category %q", r.Category)
	}
}

// Every chunk ends at a sentence where one is near, chunks overlap, and no
// text is lost.
func TestChunkText(t *testing.T) {
	text := strings.Repeat("One short sentence here. ", 400)
	chunks := chunkText(text, 1000)
	if len(chunks) < 10 {
		t.Fatalf("%d chunks", len(chunks))
	}
	for i, c := range chunks {
		if len(c) > 1000 {
			t.Fatalf("chunk %d is %d bytes", i, len(c))
		}
		if i < len(chunks)-1 && !strings.HasSuffix(c, ".") {
			t.Errorf("chunk %d ends mid-sentence: %q", i, c[len(c)-20:])
		}
	}
	if chunkText("  ", 10) != nil {
		t.Error("blank text gave chunks")
	}
}

// An unknown category is dropped, a fenced reply is read, and an empty
// document means no model call.
func TestReadDocumentEdges(t *testing.T) {
	model := &docModel{replies: []string{"```json\n{\"category\": \"poem\", \"assets\": [], \"statements\": [], \"attributes\": []}\n```"}}
	r, err := ReadDocument(context.Background(), model, "m", "u", docText, 0)
	if err != nil || r.Category != "" || len(r.Statements) != 0 {
		t.Errorf("reading %+v, %v", r, err)
	}

	idle := &docModel{}
	if _, err := ReadDocument(context.Background(), idle, "m", "u", "", 0); err != nil || len(idle.histories) != 0 {
		t.Errorf("an empty document called the model: %v", err)
	}
	if _, err := ReadDocument(context.Background(), nil, "m", "u", docText, 0); err == nil {
		t.Error("no model was accepted")
	}
}

// The prompt lists OAM asset types, OAM relations, the catalog's predicates
// and the OAM fields; the schema allows only them.
func TestDocumentPromptAndSchema(t *testing.T) {
	v := documentVocabulary()
	prompt := documentPrompt(v)
	for _, want := range []string{"unit_of", "holds_role", "staff_directory", "copied exactly", "FQDN", "Netblock",
		"-[subsidiary]-> Organization", "-[announces]-> Netblock", "founding_date", "StreetAddress"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt lacks %q", want)
		}
	}
	for _, p := range []string{"member", "manufacturer", "unit_of", "dns_record"} {
		found := false
		for _, q := range v.predicates {
			found = found || q == p
		}
		if !found {
			t.Errorf("predicate %q is not allowed", p)
		}
	}
	if !v.allows("Organization", "subsidiary", "Organization") || v.allows("Person", "subsidiary", "Organization") ||
		!v.allows("AutonomousSystem", "announces", "Netblock") || !v.allows("Organization", "unit_of", "Organization") {
		t.Error("allowed relations do not follow OAM and the catalog")
	}
	if documentSchema(v).Schema == nil {
		t.Error("no schema")
	}
}

// A reading is stored as its findings plus its category, File is_a
// <category>, each naming the version read; "other" is not stored.
func TestDocumentReadingStored(t *testing.T) {
	r := DocumentReading{Category: "annual_report", Statements: []DocumentStatement{
		{Kind: FindingRelation, Subject: "SUNY Polytechnic Institute", SubjectType: "Organization", Predicate: "unit_of",
			Object: "State University of New York", ObjectType: "Organization",
			Quote: "SUNY Polytechnic Institute is a campus of the State University of New York.", Model: "ollama/qwen3"},
		{Kind: FindingAsset, Subject: "vpn.sunyit.edu", SubjectType: "FQDN", Quote: "vpn.sunyit.edu"},
	}}
	got := r.Stored("https://www.sunyit.edu/report.pdf", "abc")
	if len(got) != 3 {
		t.Fatalf("stored %d statements, want 3", len(got))
	}
	if c := got[0]; c.Predicate != review.PredicateIsA || c.SubjectType != "File" || c.Object != "annual_report" ||
		c.SHA256 != "abc" {
		t.Fatalf("category statement %+v", c)
	}
	if s := got[1]; s.Kind != FindingRelation || s.Quote == "" || s.Model != "ollama/qwen3" || s.SHA256 != "abc" {
		t.Fatalf("statement %+v", s)
	}
	r.Category = "other"
	if len(r.Stored("u", "h")) != 2 {
		t.Error("the category other was stored")
	}
}

// A finding whose ends are common nouns, or that the text negates, is
// rejected.
func TestReadDocumentRejectsNegationsAndCommonNouns(t *testing.T) {
	text := "The College has adopted free speech policies, but not for third parties, who are not sponsored by " +
		"SUNY Polytechnic Institute or a recognized student organization. " +
		"The SUNY Poly Auxiliary Services Corporation is not affiliated with Acme Dining Inc. " +
		"The SUNY Poly Foundation is a division of SUNY Polytechnic Institute."
	reply := `{"category": "policy", "assets": [], "attributes": [], "statements": [
	 {"subject": "third parties", "subject_type": "Organization", "predicate": "member_of",
	  "object": "SUNY Polytechnic Institute", "object_type": "Organization",
	  "quote": "who are not sponsored by SUNY Polytechnic Institute"},
	 {"subject": "SUNY Poly Auxiliary Services Corporation", "subject_type": "Organization", "predicate": "partner_of",
	  "object": "Acme Dining Inc.", "object_type": "Organization",
	  "quote": "The SUNY Poly Auxiliary Services Corporation is not affiliated with Acme Dining Inc."},
	 {"subject": "SUNY Poly Foundation", "subject_type": "Organization", "predicate": "unit_of",
	  "object": "SUNY Polytechnic Institute", "object_type": "Organization",
	  "quote": "The SUNY Poly Foundation is a division of SUNY Polytechnic Institute."}
	]}`

	r, err := ReadDocument(context.Background(), &docModel{replies: []string{reply}}, "m", "u", text, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Statements) != 1 || r.Statements[0].Subject != "SUNY Poly Foundation" {
		t.Fatalf("kept %+v (rejected %q)", r.Statements, r.Rejected)
	}
	joined := strings.Join(r.Rejected, "|")
	for _, want := range []string{"is not a Organization", "negates"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no rejection for %q in %q", want, r.Rejected)
		}
	}
}

// A building, a law or a course named as an Organization, and a job title
// named as a Person, are rejected (semantics.MisnamedDocumentName); the
// organization beside them is kept.
func TestReadDocumentRejectsMisnamedAssets(t *testing.T) {
	text := "Classes in CS 101 meet in Boyd Hall. Utica University complies with the Clery Act. " +
		"Questions go to the Dean of Students."
	reply := `{"category": "policy", "assets": [
	 {"type": "Organization", "value": "Boyd Hall", "quote": "Classes in CS 101 meet in Boyd Hall."},
	 {"type": "Organization", "value": "CS 101", "quote": "Classes in CS 101 meet in Boyd Hall."},
	 {"type": "Organization", "value": "Clery Act", "quote": "Utica University complies with the Clery Act."},
	 {"type": "Person", "value": "Dean of Students", "quote": "Questions go to the Dean of Students."},
	 {"type": "Organization", "value": "Utica University", "quote": "Utica University complies with the Clery Act."}
	], "attributes": [], "statements": []}`

	r, err := ReadDocument(context.Background(), &docModel{replies: []string{reply}}, "m", "u", text, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Statements) != 1 || r.Statements[0].Kind != FindingAsset || r.Statements[0].Subject != "Utica University" {
		t.Fatalf("kept %+v (rejected %q)", r.Statements, r.Rejected)
	}
	joined := strings.Join(r.Rejected, "|")
	for _, want := range []string{"names a building", "names a course", "names a law", "names a job title"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no rejection for %q in %q", want, r.Rejected)
		}
	}
}

// A name holding a piece of a split word is not a proper name; the short
// words names hold are.
func TestFragmentedNames(t *testing.T) {
	for name, want := range map[string]bool{
		"UV CC Theat er":                true,
		"Utica Universi ty":             true,
		"Bank of Example":               false,
		"Universidad de la Costa":       false,
		"Acme & Sons":                   false,
		"AB&C":                          false,
		"UVCC":                          false,
		"Center for Corporate & Co. Ed": false,
	} {
		if got := fragmented(name); got != want {
			t.Errorf("fragmented(%q) = %v, want %v", name, got, want)
		}
	}
	if properName("UV CC Theat er") {
		t.Error("a fragmented name passed as a proper name")
	}
}

// cutModel cuts off its first reply at the token limit, as a model that
// repeats itself until num_predict stops it.
type cutModel struct{ docModel }

func (m *cutModel) Generate(ctx context.Context, h []llm.Message, t []llm.ToolSpec) (llm.Response, error) {
	resp, _ := m.docModel.Generate(ctx, h, t)
	if len(m.histories) == 1 {
		return llm.Response{Text: `{"category": "policy", "assets": [{"type": "FQDN", "value": "vpn.sunyit.edu",
		  "quote": "Staff`}, fmt.Errorf("ollama %w (num_ctx 16384, num_predict 4096)", llm.ErrReplyLength)
	}
	return resp, nil
}

// A part whose reply is cut off at the token limit is skipped, and the rest
// of the document is still read.
func TestReadDocumentSkipsCutOffReplies(t *testing.T) {
	text := strings.Repeat("Filler sentence about the campus grounds. ", 200) + docText
	reply := `{"category": "policy", "assets": [{"type": "FQDN", "value": "vpn.sunyit.edu",
	  "quote": "Staff connect remotely through vpn.sunyit.edu"}], "statements": [], "attributes": []}`
	model := &cutModel{docModel{replies: []string{reply}}}

	r, err := ReadDocument(context.Background(), model, "m", "u", text, 2000)
	if err != nil {
		t.Fatalf("a cut-off part failed the document: %v", err)
	}
	if r.Chunks != len(model.histories) || r.Chunks < 4 || len(r.Statements) != 1 {
		t.Fatalf("read %d chunks with %d requests, findings %+v", r.Chunks, len(model.histories), r.Statements)
	}
	cut := false
	for _, reason := range r.Rejected {
		cut = cut || strings.Contains(reason, "part 1: reply cut off")
	}
	if !cut {
		t.Errorf("rejected %v, want part 1 cut off", r.Rejected)
	}
}

// Control characters in extracted text become spaces before the model reads
// it, newlines and tabs stay, and a quote across one still matches.
func TestReadDocumentCleansControlCharacters(t *testing.T) {
	if got := cleanText("a\fb\x00c\x1b[0m\td\ne\u0085f"); got != "a b c [0m\td\ne f" {
		t.Errorf("cleanText = %q", got)
	}
	reply := `{"category": "policy", "assets": [{"type": "FQDN", "value": "vpn.sunyit.edu",
	  "quote": "Staff connect remotely through vpn.sunyit.edu"}], "statements": [], "attributes": []}`
	model := &docModel{replies: []string{reply}}
	text := strings.Replace(docText, "Staff connect remotely", "Staff connect\fremotely", 1)
	r, err := ReadDocument(context.Background(), model, "m", "u", text, 0)
	if err != nil || len(r.Statements) != 1 {
		t.Fatalf("findings %+v, %v", r.Statements, err)
	}
	if strings.ContainsRune(model.histories[0][1].Text, '\f') {
		t.Error("the model was sent a control character")
	}
}

// A reading capped at a number of parts says where it stopped, and the next
// reading, starting there, reads the rest of the document: every part is read
// once across the two.
func TestReadingResumesWhereItStopped(t *testing.T) {
	text := strings.Repeat("Filler sentence about the campus grounds. ", 200) + docText
	empty := `{"category": "other", "assets": [], "statements": [], "attributes": []}`
	all := len(chunkSpans(cleanText(text), 2000))
	if all < 4 {
		t.Fatalf("%d parts; the test needs a long document", all)
	}

	first := &docModel{replies: []string{empty}}
	r, err := readDocument(context.Background(), first, "m", "u", text, 2000, readLimits{maxChunks: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Chunks != 2 || r.Through <= 0 {
		t.Fatalf("a reading capped at 2 parts read %d and stopped at %d", r.Chunks, r.Through)
	}

	rest := &docModel{replies: []string{empty}}
	r2, err := readDocument(context.Background(), rest, "m", "u", text, 2000, readLimits{from: r.Through}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Through != 0 || r.Chunks+r2.Chunks != all {
		t.Errorf("the two readings read %d+%d of %d parts (second stopped at %d)", r.Chunks, r2.Chunks, all,
			r2.Through)
	}
	if !strings.Contains(rest.histories[len(rest.histories)-1][1].Text, "vpn.sunyit.edu") {
		t.Error("the continued reading never reached the end of the document")
	}
	if !strings.Contains(rest.histories[0][1].Text, fmt.Sprintf("Part 3 of %d", all)) {
		t.Errorf("the continued reading does not number its first part as the third: %q",
			rest.histories[0][1].Text[:60])
	}
}

// Past its time limit a reading starts no further part; the part in progress
// counts, so a reading always makes progress.
func TestReadingStopsAtItsTimeLimit(t *testing.T) {
	text := strings.Repeat("Filler sentence about the campus grounds. ", 200) + docText
	model := &docModel{replies: []string{`{"category": "other", "assets": [], "statements": [], "attributes": []}`}}

	r, err := readDocument(context.Background(), model, "m", "u", text, 2000, readLimits{timeout: time.Nanosecond},
		nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Chunks != 1 || r.Through <= 0 {
		t.Errorf("a reading past its time limit read %d parts and stopped at %d, want 1 part", r.Chunks, r.Through)
	}
}
