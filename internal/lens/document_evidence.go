// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// Document evidence for the classifiers: the relation findings the document
// model stored on Files, found by predicate through a value search, so the
// duplicate and ownership searches count what documents state without
// reading every File. Every document signal is supporting (see
// document_signals.json), and none may cause or help cause an automatic
// write (WithoutDocumentSignals).

// DocumentSignalKind is the kind of every signal that comes from a document
// finding.
const DocumentSignalKind = "document"

// matchDocumentStatement is the matcher of the catalog signals document
// findings give.
const matchDocumentStatement = "document_statement"

// The predicates whose findings the classifiers read.
var (
	docFormerPredicates   = []string{"formerly_known_as", "merged_with"}
	docParentPredicates   = []string{"subsidiary_of", "acquired_by", "owned_by", "unit_of"}
	docOperatorPredicates = []string{"operated_by"}
)

// docFinding is one relation finding and the document it came from.
type docFinding struct {
	st     docStatement
	fileID string
	url    string
}

// version is the document version the finding was read from.
func (f docFinding) version() string {
	if f.st.SHA256 != "" {
		return f.st.SHA256
	}
	return f.fileID
}

// documentFindings returns the relation findings with the given predicates,
// from every File a value search finds holding them. A repository without
// value searches gives none.
func documentFindings(ctx context.Context, g graph.Graph, predicates []string) ([]docFinding, error) {
	vs, ok := g.(ValueSearcher)
	if !ok {
		return nil, nil
	}

	var out []docFinding
	seen := map[string]bool{}
	for _, p := range predicates {
		files, _, err := vs.FindByTagValue(ctx, "File", propDocStatement, `"predicate":"`+p+`"`, true, 0)
		if errors.Is(err, ErrValueSearchUnsupported) {
			return nil, nil
		} else if err != nil {
			return out, err
		}

		for _, f := range files {
			if seen[f.ID] {
				continue
			}
			seen[f.ID] = true
			ev, err := g.Evidence(ctx, f.ID, allEvidence)
			if err != nil {
				return out, err
			}
			fileURL := graph.ContentString(f, "url")
			stale := StaleDocument(documentDated(ev), time.Now())
			for _, v := range propertyValues(ev, propDocStatement) {
				var st docStatement
				if json.Unmarshal([]byte(v), &st) != nil || st.Kind != "relation" ||
					!slices.Contains(predicates, st.Predicate) || staleFinding(stale, st.Predicate) ||
					st.Object == DocumentPublisher || st.Subject == DocumentPublisher {
					// the publisher placeholder names no organization by name
					continue
				}
				out = append(out, docFinding{st: st, fileID: f.ID, url: fileURL})
			}
		}
	}
	return out, nil
}

// docFold folds a name for exact comparison: case and runs of white space
// only. Legal forms are not removed: "Acme Inc" is not "Acme LLC".
func docFold(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// WithoutDocumentSignals returns the signals that do not come from
// documents or from an organization's own declarations (a bug-bounty
// program's scope). What may be written without a person's review is decided
// on these alone: such evidence can raise a candidate to review and add to
// its score, but never causes or helps cause an automatic write.
func WithoutDocumentSignals(signals []GapSignal) []GapSignal {
	out := make([]GapSignal, 0, len(signals))
	for _, s := range signals {
		if !isDocumentSignal(s) {
			out = append(out, s)
		}
	}
	return out
}

// isDocumentSignal reports whether a signal is review-only (ReviewOnlyKind),
// by its kind or, for a signal read back without one, its catalog entry.
func isDocumentSignal(s GapSignal) bool {
	if ReviewOnlyKind(s.Kind) {
		return true
	}
	if def, ok := LookupOwnershipSignal(s.Signal); ok && ReviewOnlyKind(def.Kind) {
		return true
	}
	def, ok := DuplicateSignal(s.Signal)
	return ok && ReviewOnlyKind(def.Kind)
}

// ReviewOnlyKind reports whether signals of a kind are never decided on
// without a person's review: document findings and an organization's own
// declarations.
func ReviewOnlyKind(kind string) bool {
	return kind == DocumentSignalKind || kind == DeclarationSignalKind
}

// docLink is what documents state relates one organization name to another.
type docLink struct {
	former   bool
	parent   bool
	versions map[string]bool
	text     string
	url      string
	// fromName and toName are the two names as the document wrote them,
	// for exact lookups (the index is keyed by folded names).
	fromName, toName string
}

// docLinks maps a folded organization name to the folded names documents
// relate it to.
type docLinks map[string]map[string]*docLink

// buildDocLinks indexes the organization-to-organization findings: a former
// name or merger, which counts toward a merge, and a parent, subsidiary,
// acquirer, owner or unit, which counts against one. Both directions are
// indexed.
func buildDocLinks(findings []docFinding) docLinks {
	out := docLinks{}
	for _, f := range findings {
		if f.st.SubjectType != "Organization" || f.st.ObjectType != "Organization" {
			continue
		}
		a, b := docFold(f.st.Subject), docFold(f.st.Object)
		if a == "" || b == "" || a == b {
			continue
		}
		former := slices.Contains(docFormerPredicates, f.st.Predicate)
		names := map[string]string{a: strings.Join(strings.Fields(f.st.Subject), " "),
			b: strings.Join(strings.Fields(f.st.Object), " ")}
		for _, pair := range [][2]string{{a, b}, {b, a}} {
			m := out[pair[0]]
			if m == nil {
				m = map[string]*docLink{}
				out[pair[0]] = m
			}
			l := m[pair[1]]
			if l == nil {
				l = &docLink{versions: map[string]bool{}, url: f.url, fromName: names[pair[0]],
					toName: names[pair[1]], text: fmt.Sprintf("%q %s %q", f.st.Subject, f.st.Predicate, f.st.Object)}
				m[pair[1]] = l
			}
			if former {
				l.former = true
			} else {
				l.parent = true
			}
			l.versions[f.version()] = true
		}
	}
	return out
}

// documentSignals adds the signals documents give an ownership-gap search:
// a host name or URL a document says the subject operates, when the
// organization is named exactly by its name or legal name and the asset is
// already stored. The weight gains the first-party bonus when the document
// is published on one of the subject's own domains.
func (g *gapSearch) documentSignals() error {
	findings, err := documentFindings(g.w.ctx, g.w.graph, docOperatorPredicates)
	if err != nil || len(findings) == 0 {
		return err
	}
	resolver, ok := g.w.graph.(graph.AssetResolver)
	if !ok {
		return nil
	}

	owner := map[string]bool{}
	for _, field := range []string{"name", "legal_name"} {
		if n := docFold(graph.ContentString(g.owner, field)); n != "" {
			owner[n] = true
		}
	}

	type operated struct {
		asset      graph.Asset
		versions   map[string]bool
		firstParty bool
		via        string
	}
	found := map[string]*operated{}
	var order []string
	for _, f := range findings {
		if f.st.ObjectType != "Organization" || !owner[docFold(f.st.Object)] {
			continue
		}
		sel := graph.AssetSelector{Type: f.st.SubjectType}
		switch f.st.SubjectType {
		case "FQDN":
			sel.Field, sel.Value = "name", strings.ToLower(strings.TrimSuffix(strings.TrimSpace(f.st.Subject), "."))
		case "URL":
			sel.Field, sel.Value = "url", strings.TrimSpace(f.st.Subject)
		default:
			continue
		}
		res, err := resolver.ResolveAsset(g.w.ctx, sel, 2)
		if err != nil || res.Status != "matched" || len(res.Candidates) != 1 {
			continue
		}

		a := res.Candidates[0].Asset
		o, ok := found[a.ID]
		if !ok {
			o = &operated{asset: a, versions: map[string]bool{},
				via: fmt.Sprintf("%s %q is operated by %q, in %s", f.st.SubjectType, f.st.Subject, f.st.Object, f.url)}
			found[a.ID] = o
			order = append(order, a.ID)
		}
		o.versions[f.version()] = true
		o.firstParty = o.firstParty || g.firstParty(f.url)
	}

	for _, id := range order {
		o := found[id]
		g.addWeighted(o.asset, sigDocumentOperator, o.via, nil, DocumentWeight(o.firstParty, len(o.versions)))
	}
	return nil
}

// sigDocumentOperator is the ownership signal a document's operated_by
// finding gives.
const sigDocumentOperator = "document-operator"

// firstParty reports whether a document URL is on one of the subject's own
// registered domains.
func (g *gapSearch) firstParty(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	for _, d := range g.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// addWeighted adds a signal whose weight is below its catalog weight, as a
// document signal's is.
func (g *gapSearch) addWeighted(a graph.Asset, id, via string, witness []graph.WitnessEdge, weight float64) {
	g.add(a, id, via, witness)
	c, ok := g.found[a.ID]
	if !ok {
		return
	}
	for i := range c.Signals {
		if c.Signals[i].Signal == id && c.Signals[i].Via == via {
			c.Signals[i].Weight = weight
		}
	}
}
