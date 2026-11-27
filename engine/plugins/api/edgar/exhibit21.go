// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package edgar

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/biter777/countries"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/net/html"
)

// subsidiaryExhibits are the annual reports that list a registrant's
// subsidiaries and the exhibit type that holds the list: Regulation S-K Item
// 601(b)(21) for a 10-K (Exhibit 21), and Form 20-F Instructions as to
// Exhibits, item 8 for a foreign private issuer (Exhibit 8).
var subsidiaryExhibits = map[string]string{
	"10-K":    "EX-21",
	"10-K405": "EX-21",
	"20-F":    "EX-8",
}

const (
	// maxSubsidiaries guards against a misread exhibit; the largest filers
	// list a few thousand subsidiaries.
	maxSubsidiaries = 5000
	// maxExhibitBytes bounds an exhibit document.
	maxExhibitBytes = 4 << 20
)

// subsidiary is one entry of a subsidiary list.
type subsidiary struct {
	name         string
	jurisdiction string // a GLEIF-style code when recognized, else as written
}

// storeSubsidiaries reads the subsidiary list of the registrant's latest
// annual report and stores each subsidiary as an Organization joined to the
// registrant by a subsidiary edge. It returns the subsidiaries stored.
func (h *filings) storeSubsidiaries(e *et.Event, orgent *dbt.Entity, cik string, sub *submissions) []*dbt.Entity {
	accession, prefix := latestAnnualReport(sub)
	if accession == "" {
		return nil
	}

	cikDir := strings.TrimLeft(cik, "0")
	nodash := strings.ReplaceAll(accession, "-", "")
	index, err := h.get(e, fmt.Sprintf("%s/Archives/edgar/data/%s/%s/%s-index.htm", h.plugin.www, cikDir,
		nodash, accession))
	if err != nil {
		return nil
	}

	var subs []subsidiary
	for _, doc := range exhibitDocuments(index, prefix) {
		body, err := h.get(e, h.plugin.www+doc)
		if err != nil || len(body) > maxExhibitBytes {
			continue
		}
		subs = append(subs, parseSubsidiaries(body)...)
	}

	src := &et.Source{Name: h.plugin.source.Name, Confidence: h.plugin.source.Confidence}
	seen := map[string]bool{}
	var stored []*dbt.Entity
	for _, s := range subs {
		key := strings.ToLower(s.name)
		if seen[key] || len(stored) >= maxSubsidiaries {
			continue
		}
		seen[key] = true

		o := &oamorg.Organization{Name: s.name, Jurisdiction: s.jurisdiction}
		if ent, err := org.CreateOrgAsset(e.Session, orgent, &general.SimpleRelation{Name: "subsidiary"},
			o, src); err == nil && ent != nil {
			stored = append(stored, ent)
		}
	}
	return stored
}

// latestAnnualReport returns the accession number of the newest annual report
// that lists subsidiaries, and the exhibit type that lists them. Amendments
// are skipped: they usually refile only some parts.
func latestAnnualReport(sub *submissions) (string, string) {
	r := sub.Filings.Recent
	if len(r.AccessionNumber) < len(r.Form) {
		return "", ""
	}

	// The recent filings are listed newest first.
	for i, form := range r.Form {
		if prefix, ok := subsidiaryExhibits[form]; ok && r.AccessionNumber[i] != "" {
			return r.AccessionNumber[i], prefix
		}
	}
	return "", ""
}

// exhibitDocuments returns the archive paths of a filing's documents whose
// type starts with prefix, read from the filing index page's document table
// (columns Seq, Description, Document, Type, Size).
func exhibitDocuments(index, prefix string) []string {
	root, err := html.Parse(strings.NewReader(index))
	if err != nil {
		return nil
	}

	var docs []string
	for _, tr := range elements(root, "tr") {
		var cells []*html.Node
		for c := tr.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == "td" {
				cells = append(cells, c)
			}
		}
		if len(cells) < 4 || !exhibitType(nodeText(cells[3]), prefix) {
			continue
		}

		for _, a := range elements(cells[2], "a") {
			href := strings.TrimPrefix(attr(a, "href"), "/ix?doc=")
			if strings.HasPrefix(href, "/Archives/") {
				docs = append(docs, href)
				break
			}
		}
	}
	return docs
}

// exhibitType reports whether a document type is the exhibit: "EX-21" matches
// "EX-21" and "EX-21.1" but not "EX-210".
func exhibitType(t, prefix string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	if !strings.HasPrefix(t, prefix) {
		return false
	}
	rest := t[len(prefix):]
	return rest == "" || rest[0] == '.'
}

// parseSubsidiaries reads a subsidiary list. Most exhibits are a table with a
// row per subsidiary (name first, then its jurisdiction and sometimes the
// ownership); the rest are lines of text, with the jurisdiction in
// parentheses, after a comma or dash, or in a column of its own.
func parseSubsidiaries(doc string) []subsidiary {
	if !strings.Contains(doc, "<") {
		return parseLines(strings.Split(doc, "\n"))
	}

	root, err := html.Parse(strings.NewReader(doc))
	if err != nil {
		return nil
	}

	var subs []subsidiary
	rows := elements(root, "tr")
	for _, tr := range rows {
		var cells []string
		for c := tr.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && (c.Data == "td" || c.Data == "th") {
				if t := cleanCell(nodeText(c)); t != "" {
					cells = append(cells, t)
				}
			}
		}

		switch {
		case len(cells) >= 2:
			if s, ok := tableRow(cells); ok {
				subs = append(subs, s)
			}
		case len(cells) == 1:
			subs = append(subs, parseLines([]string{cells[0]})...)
		}
	}
	if len(rows) > 0 && len(subs) > 0 {
		return subs
	}

	return parseLines(blockLines(root))
}

// tableRow reads a table row: the first cell is the name, and the
// jurisdiction is the first later cell that names one.
func tableRow(cells []string) (subsidiary, bool) {
	// a leading row number is not the name
	if strings.Trim(cells[0], "0123456789.()") == "" {
		cells = cells[1:]
		if len(cells) == 0 {
			return subsidiary{}, false
		}
	}

	name := cleanName(cells[0])
	if !plausibleName(name, false) {
		return subsidiary{}, false
	}

	for _, c := range cells[1:] {
		if code, ok := resolveJurisdiction(c); ok {
			return subsidiary{name: name, jurisdiction: code}, true
		}
	}
	// A two-column row whose second cell is a short word is a jurisdiction
	// the lookups do not know; keep it as written.
	if len(cells) == 2 && len(cells[1]) <= 40 && !strings.ContainsAny(cells[1], "%0123456789") {
		return subsidiary{name: name, jurisdiction: cells[1]}, true
	}
	return subsidiary{name: name}, true
}

var (
	trailingParens = regexp.MustCompile(`^(.*\S)\s*\(([^()]+)\)\s*$`)
	columnGap      = regexp.MustCompile(`\s{2,}|\t|\.{3,}`)
	leadingMarker  = regexp.MustCompile(`^(?:[-•·*–—]+|\(?\d{1,3}[.)])\s*`)
)

// parseLines reads subsidiaries written one per line.
func parseLines(lines []string) []subsidiary {
	var subs []subsidiary
	for _, line := range lines {
		line = leadingMarker.ReplaceAllString(strings.TrimSpace(line), "")
		if line == "" {
			continue
		}
		if s, ok := parseLine(line); ok {
			subs = append(subs, s)
		}
	}
	return subs
}

func parseLine(line string) (subsidiary, bool) {
	// Name (Jurisdiction)
	if m := trailingParens.FindStringSubmatch(line); m != nil {
		if code, ok := resolveJurisdiction(m[2]); ok {
			if name := cleanName(m[1]); plausibleName(name, false) {
				return subsidiary{name: name, jurisdiction: code}, true
			}
		}
	}
	// Name<two or more spaces, a tab or dot leaders>Jurisdiction
	if parts := columnGap.Split(line, -1); len(parts) >= 2 {
		var cells []string
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				cells = append(cells, p)
			}
		}
		if len(cells) >= 2 {
			if code, ok := resolveJurisdiction(cells[len(cells)-1]); ok {
				if name := cleanName(cells[0]); plausibleName(name, false) {
					return subsidiary{name: name, jurisdiction: code}, true
				}
			}
		}
	}
	// Name, Jurisdiction / Name - Jurisdiction
	for _, sep := range []string{" - ", " – ", " — ", ", "} {
		if i := strings.LastIndex(line, sep); i > 0 {
			if code, ok := resolveJurisdiction(line[i+len(sep):]); ok {
				if name := cleanName(line[:i]); plausibleName(name, false) {
					return subsidiary{name: name, jurisdiction: code}, true
				}
			}
		}
	}
	// A name alone counts only when it carries a company form.
	if name := cleanName(line); plausibleName(name, true) {
		return subsidiary{name: name}, true
	}
	return subsidiary{}, false
}

// entityWords follow a jurisdiction in phrases such as "a Delaware limited
// liability company".
var entityWords = []string{"limited liability company", "limited partnership", "general partnership",
	"partnership", "corporation", "company", "limited", "llc", "corp", "trust", "bank"}

// resolveJurisdiction returns the code for a jurisdiction phrase: a state,
// province or United Kingdom word from the catalog, or a country name.
func resolveJurisdiction(s string) (string, bool) {
	s = strings.TrimSpace(strings.Trim(strings.TrimSpace(s), ".,;:*"))
	if s == "" || len(s) > 60 {
		return "", false
	}

	try := func(w string) (string, bool) {
		w = strings.TrimSpace(w)
		if w == "" {
			return "", false
		}
		if code := semantics.JurisdictionCode(w); code != "" {
			return code, true
		}
		// The country lookup also takes two- and three-letter codes, which
		// would read "Co" or "AS" as countries, so it gets whole names only.
		if letters(w) < 4 {
			return "", false
		}
		if c := countries.ByName(w); c.IsValid() {
			return c.Alpha2(), true
		}
		return "", false
	}

	if code, ok := try(s); ok {
		return code, true
	}

	l := strings.ToLower(s)
	for _, p := range []string{"organized in ", "incorporated in ", "a ", "an ", "the "} {
		l = strings.TrimPrefix(l, p)
	}
	for _, w := range entityWords {
		l = strings.TrimSuffix(strings.TrimSpace(l), " "+w)
	}
	if l != strings.ToLower(s) {
		return try(l)
	}
	return "", false
}

var (
	footnotes  = regexp.MustCompile(`(?:\s*\(\d{1,2}\)|\s*\([a-z]\)|[*†‡§¹²³]+)\s*$`)
	spaceRun   = regexp.MustCompile(`\s+`)
	companyEnd = regexp.MustCompile(`(?i)\b(?:inc|incorporated|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|` +
		`plc|lp|l\.p|llp|gmbh|ag|sa|s\.a|sas|s\.a\.s|sarl|s\.a\.r\.l|srl|s\.r\.l|spa|s\.p\.a|bv|b\.v|nv|n\.v|` +
		`ab|as|a/s|asa|oy|oyj|kk|k\.k|pty|pte|sdn bhd|bhd|sl|s\.l|sau|s\.a\.u|kft|zrt|sp\. z o\.o|s\.r\.o|` +
		`ltda|s\.a\. de c\.v|de c\.v|trust|holdings|group|partners)\.?$`)
	// headings name no subsidiary even when they end in a company form
	// ("Subsidiaries of Example Inc."); headerWords are heading words that
	// can also appear in a name with a company form.
	headings    = []string{"subsidiaries of", "subsidiary of", "list of", "name of", "exhibit 21", "exhibit 8"}
	headerWords = []string{"jurisdiction", "state of", "country of", "incorporation", "organized",
		"subsidiaries", "exhibit", "percent", "ownership", "place of"}
)

// cleanCell collapses a cell's whitespace and drops non-breaking spaces.
func cleanCell(s string) string {
	return strings.TrimSpace(spaceRun.ReplaceAllString(strings.ReplaceAll(s, " ", " "), " "))
}

// cleanName drops footnote markers and trailing punctuation from a name.
func cleanName(s string) string {
	s = cleanCell(s)
	for {
		t := strings.TrimSpace(footnotes.ReplaceAllString(s, ""))
		t = strings.TrimRight(t, ",;:")
		if t == s {
			return s
		}
		s = t
	}
}

// plausibleName reports whether s reads as an organization name rather than a
// heading or stray text. needForm requires a company form at its end.
func plausibleName(s string, needForm bool) bool {
	if len(s) < 3 || len(s) > 150 || !strings.ContainsFunc(s, func(r rune) bool {
		return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r > 0x7f
	}) {
		return false
	}

	l := strings.ToLower(s)
	for _, w := range headings {
		if strings.Contains(l, w) {
			return false
		}
	}

	form := companyEnd.MatchString(s)
	if needForm && !form {
		return false
	}
	if _, ok := resolveJurisdiction(s); ok {
		return false // a jurisdiction alone, such as a heading row
	}
	if !form {
		for _, w := range headerWords {
			if strings.Contains(l, w) {
				return false
			}
		}
	}
	return true
}

// blockLines returns the text of a document's paragraphs, divisions and list
// items, split at line breaks.
func blockLines(root *html.Node) []string {
	var lines []string
	var cur strings.Builder
	flush := func() {
		if t := cleanCell(cur.String()); t != "" {
			lines = append(lines, t)
		}
		cur.Reset()
	}

	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			cur.WriteString(n.Data)
			return
		}
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "head":
				return
			case "br":
				flush()
				return
			case "p", "div", "li", "pre", "h1", "h2", "h3", "h4", "tr":
				flush()
				defer flush()
			}
		}
		if n.Type == html.ElementNode && n.Data == "pre" {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.TextNode {
					for _, l := range strings.Split(c.Data, "\n") {
						cur.WriteString(l)
						flush()
					}
				}
			}
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(root)
	flush()
	return lines
}

func letters(s string) int {
	var n int
	for _, r := range s {
		if unicode.IsLetter(r) {
			n++
		}
	}
	return n
}

func elements(n *html.Node, tag string) []*html.Node {
	var out []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == tag {
			out = append(out, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return out
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		if n.Type == html.ElementNode && n.Data == "br" {
			b.WriteByte(' ')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}
