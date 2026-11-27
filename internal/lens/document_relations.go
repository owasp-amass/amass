// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// DocumentRelationKind is the correlator kind of the relationships documents
// state: the prefix of their proposal IDs (doc_relation-<hash>).
const DocumentRelationKind = "doc_relation"

// docRelationMaxCited bounds the documents cited on one proposal.
const docRelationMaxCited = 5

// documentSignalsJSON defines what a document finding counts for (principle
// 8: every signal is data with its rationale).
var documentSignalsJSON = semantics.File("document_signals.json")

// DocumentSignal is one kind of document finding that counts as evidence for
// a relationship between two stored assets.
type DocumentSignal struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Predicates         []string `json:"predicates"`
	SubjectType        string   `json:"subject_type"`
	ObjectType         string   `json:"object_type"`
	Label              string   `json:"label"`
	Direction          string   `json:"direction"`
	Finds              string   `json:"finds"`
	Rationale          string   `json:"rationale"`
	Guards             []string `json:"guards"`
	CounterIndications []string `json:"counter_indications"`
}

// DocumentWeights are how much a document finding weighs: always a
// supporting signal, more when first-party or corroborated, never past Cap.
type DocumentWeights struct {
	Base               float64 `json:"base"`
	FirstPartyBonus    float64 `json:"first_party_bonus"`
	CorroborationBonus float64 `json:"corroboration_bonus"`
	Cap                float64 `json:"cap"`
}

type documentSignalCatalog struct {
	License string           `json:"_license"`
	About   string           `json:"_about"`
	Weights DocumentWeights  `json:"weights"`
	Signals []DocumentSignal `json:"signals"`
}

var loadDocumentSignals = sync.OnceValues(func() (documentSignalCatalog, error) {
	var c documentSignalCatalog
	if err := graph.DecodeStrict(documentSignalsJSON, &c); err != nil {
		return c, fmt.Errorf("document_signals.json: %w", err)
	}
	return c, validateDocumentSignals(c)
})

// validateDocumentSignals checks the catalog: weights that keep every
// document signal supporting, and signals whose predicates the document
// model reads, with the OAM relation the predicate catalog names for them.
func validateDocumentSignals(c documentSignalCatalog) error {
	w := c.Weights
	switch {
	case w.Base <= 0 || w.FirstPartyBonus < 0 || w.CorroborationBonus < 0:
		return errors.New("document_signals.json: weights must be positive")
	case w.Cap < w.Base || w.Cap > documentSupportingMax:
		return fmt.Errorf("document_signals.json: cap must be from base to %.2f, below every strong signal",
			documentSupportingMax)
	}

	rules := semantics.StatementPredicateRules()
	ids := map[string]bool{}
	predicates := map[string]bool{}
	for _, s := range c.Signals {
		switch {
		case s.ID == "" || ids[s.ID]:
			return fmt.Errorf("document_signals.json: missing or repeated id %q", s.ID)
		case s.Label == "" || (s.Direction != "forward" && s.Direction != "inverse"):
			return fmt.Errorf("document signal %s: a label and a forward or inverse direction are required", s.ID)
		case s.SubjectType == "" || s.ObjectType == "" || len(s.Predicates) == 0:
			return fmt.Errorf("document signal %s: predicates, subject_type and object_type are required", s.ID)
		case s.Title == "" || s.Rationale == "" || len(s.Guards) == 0:
			return fmt.Errorf("document signal %s: a title, rationale and guards are required", s.ID)
		}
		ids[s.ID] = true

		for _, name := range s.Predicates {
			p, ok := rules.Predicate(name)
			if !ok {
				return fmt.Errorf("document signal %s: unknown predicate %q", s.ID, name)
			}
			if predicates[name] {
				return fmt.Errorf("document signal %s: predicate %q is claimed twice", s.ID, name)
			}
			predicates[name] = true
			if !contains(p.SubjectTypes, s.SubjectType) || !contains(p.ObjectTypes, s.ObjectType) {
				return fmt.Errorf("document signal %s: %s does not relate %s to %s", s.ID, name, s.SubjectType,
					s.ObjectType)
			}
			if p.OAM != nil && (p.OAM.Label != s.Label || p.OAM.Direction != s.Direction) {
				return fmt.Errorf("document signal %s: %s is recorded as %s (%s), not %s (%s)", s.ID, name,
					p.OAM.Label, p.OAM.Direction, s.Label, s.Direction)
			}
		}
	}
	return nil
}

// documentSupportingMax is the most a document signal may weigh: below the
// weakest strong signal in the catalogs (0.35).
const documentSupportingMax = 0.3

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// DocumentSignals returns the document signal catalog.
func DocumentSignals() []DocumentSignal {
	c, err := loadDocumentSignals()
	if err != nil {
		panic(err)
	}
	return c.Signals
}

// DocumentSignalWeights returns how much document findings weigh.
func DocumentSignalWeights() DocumentWeights {
	c, err := loadDocumentSignals()
	if err != nil {
		panic(err)
	}
	return c.Weights
}

// documentSignalFor returns the signal a finding's predicate and types count
// for.
func documentSignalFor(predicate, subjectType, objectType string) (DocumentSignal, bool) {
	for _, s := range DocumentSignals() {
		if s.SubjectType == subjectType && s.ObjectType == objectType && contains(s.Predicates, predicate) {
			return s, true
		}
	}
	return DocumentSignal{}, false
}

// DocumentWeight is how much a document finding weighs: the base weight, the
// first-party bonus when the document is published on a domain the subject
// controls, the corroboration bonus when two or more distinct document
// versions state it, capped.
func DocumentWeight(firstParty bool, versions int) float64 {
	w := DocumentSignalWeights()
	v := w.Base
	if firstParty {
		v += w.FirstPartyBonus
	}
	if versions >= 2 {
		v += w.CorroborationBonus
	}
	return math.Min(v, w.Cap)
}

// docStatement is a stored finding, as the doc_statement property holds it
// (review.StoredStatement; the lens package cannot import review).
type docStatement struct {
	Kind        string `json:"kind"`
	Subject     string `json:"subject"`
	SubjectType string `json:"subject_type"`
	Predicate   string `json:"predicate"`
	Object      string `json:"object"`
	ObjectType  string `json:"object_type"`
	SHA256      string `json:"sha256"`
}

// docRelationGraph is what the document relation correlator reads: the
// graph, and exact lookups of organizations and other assets.
type docRelationGraph interface {
	graph.Graph
	graph.OrganizationResolver
	graph.AssetResolver
}

// FindDocumentRelations proposes the relationships the documents a domain or
// organization publishes state between stored assets: a unit and its parent,
// a subsidiary and its parent, a funder, a person's role, an address. A
// finding counts only when each name resolves to exactly one stored asset by
// exact name; the documents are the subject's own, so each finding gets the
// first-party bonus, and one stated by two or more distinct document versions
// the corroboration bonus. Every candidate is a review-gated proposal: nothing
// is written until a reviewer accepts it. It reads only.
func FindDocumentRelations(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (RelationReport, error) {
	report := RelationReport{Kind: DocumentRelationKind, Candidates: []RelationCandidate{}}
	if _, err := loadDocumentSignals(); err != nil {
		return report, err
	}
	dg, ok := g.(docRelationGraph)
	if !ok {
		return report, errors.New("document relations need exact organization and asset lookups")
	}

	sources, publisher, err := documentSourcesOf(ctx, g, schema, root, limits)
	if err != nil {
		return report, err
	}

	r := &docRelations{ctx: ctx, g: dg, publisher: publisher, resolved: map[string]docEnd{},
		found: map[string]*docRelation{}, linked: map[string]bool{}}
	for _, src := range sources {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		ev, err := g.Evidence(ctx, src.FileID, allEvidence)
		if err != nil {
			return report, err
		}
		values := propertyValues(ev, propDocStatement)
		for _, v := range values {
			var st docStatement
			if json.Unmarshal([]byte(v), &st) != nil || st.Kind != "relation" || staleFinding(src.Stale, st.Predicate) {
				continue
			}
			if err := r.add(src, st); err != nil {
				return report, err
			}
		}
	}

	for _, d := range r.found {
		report.Candidates = append(report.Candidates, d.candidate())
	}
	sort.Slice(report.Candidates, func(i, j int) bool {
		a, b := report.Candidates[i], report.Candidates[j]
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return a.From+a.Label+a.To < b.From+b.Label+b.To
	})
	return report, nil
}

// docEnd is a name in a finding resolved to one stored asset, or not.
type docEnd struct {
	asset graph.Asset
	ok    bool
}

// docRelation is one proposed relationship and the documents stating it. A
// destination with no ID is a unit to create on approval.
type docRelation struct {
	signal   DocumentSignal
	from, to graph.Asset
	versions map[string]bool
	files    map[string]bool
	cited    []string
}

func (d *docRelation) candidate() RelationCandidate {
	weight := DocumentWeight(true, len(d.versions))
	files := make([]string, 0, len(d.files))
	for id := range d.files {
		files = append(files, id)
	}
	sort.Strings(files)
	c := RelationCandidate{
		FromID:      d.from.ID,
		From:        graph.AssetLabel(d.from),
		Label:       d.signal.Label,
		ToID:        d.to.ID,
		To:          graph.AssetLabel(d.to),
		Confidence:  documentConfidence(weight),
		Signals:     d.cited,
		EvidenceIDs: files,
	}
	if d.to.ID == "" {
		name := graph.ContentString(d.to, "name")
		c.To = name + " (new unit)"
		c.NewTo = &NewAsset{Type: d.to.Type, Key: d.to.Key, Name: name}
	}
	return c
}

// documentConfidence is the confidence written on an accepted edge: twice the
// signal's weight, so a first-party finding confirmed by a reviewer is 40 and
// a corroborated one 50 — below the 70 of an org-unit backed by a strong
// shared link.
func documentConfidence(weight float64) int {
	return int(math.Round(weight * 200))
}

type docRelations struct {
	ctx context.Context
	g   docRelationGraph
	// publisher is the organization that published the documents read, for
	// findings that name it as DocumentPublisher
	publisher graph.Asset
	resolved  map[string]docEnd
	found     map[string]*docRelation
	linked    map[string]bool
}

// add counts one finding of one document toward the relationship it states.
func (r *docRelations) add(src DocumentSource, st docStatement) error {
	sig, ok := documentSignalFor(st.Predicate, st.SubjectType, st.ObjectType)
	if !ok {
		return nil
	}
	if st.Subject == DocumentPublisher {
		return nil
	}
	obj, err := r.resolve(st.ObjectType, st.Object)
	if err != nil || !obj.ok {
		return err
	}
	subj, err := r.resolve(st.SubjectType, st.Subject)
	if err != nil {
		return err
	}
	// a unit of the publisher: one no source has stored, or one of that
	// name stored under another organization, is proposed as a new unit
	if sig.Label == "org_unit" && sig.Direction == "inverse" && r.publisher.ID != "" &&
		obj.asset.ID == r.publisher.ID {
		if subj.ok {
			other, err := r.unitOfOther(subj.asset, obj.asset)
			if err != nil {
				return err
			}
			subj.ok = !other
		}
		if !subj.ok {
			return r.addNewUnit(src, st, sig, obj.asset)
		}
	}
	if !subj.ok {
		return nil
	}

	from, to := subj.asset, obj.asset
	if sig.Direction == "inverse" {
		from, to = to, from
	}
	if from.ID == to.ID {
		return nil
	}
	linked, err := r.isLinked(from.ID, to.ID, sig.Label)
	if err != nil || linked {
		return err
	}

	r.count(src, st, sig, from.ID+"\x00"+sig.Label+"\x00"+to.ID, from, to)
	return nil
}

// count adds one document's finding to the relationship found under key.
func (r *docRelations) count(src DocumentSource, st docStatement, sig DocumentSignal, key string,
	from, to graph.Asset) {
	d, ok := r.found[key]
	if !ok {
		d = &docRelation{signal: sig, from: from, to: to, versions: map[string]bool{}, files: map[string]bool{}}
		r.found[key] = d
	}
	version := st.SHA256
	if version == "" {
		version = src.SHA256
	}
	if version == "" {
		version = src.FileID
	}
	d.versions[version] = true
	if !d.files[src.FileID] {
		d.files[src.FileID] = true
		if len(d.cited) < docRelationMaxCited {
			object := st.Object
			if object == DocumentPublisher {
				object = "its publisher, " + graph.AssetLabel(from)
			}
			d.cited = append(d.cited, fmt.Sprintf("%s: %q %s %q, in %s", sig.Title, st.Subject, st.Predicate,
				object, src.URL))
		}
	}
}

// resolve finds the one stored asset a name in a finding names, by exact
// name: an organization by name or legal name, a person by full name, an
// address by its text. A name that matches none, or more than one, resolves
// to nothing, so evidence never attaches to the wrong asset.
func (r *docRelations) resolve(assetType, name string) (docEnd, error) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return docEnd{}, nil
	}
	if name == DocumentPublisher {
		return docEnd{asset: r.publisher, ok: assetType == "Organization" && r.publisher.ID != ""}, nil
	}
	key := assetType + "\x00" + strings.ToLower(name)
	if end, ok := r.resolved[key]; ok {
		return end, nil
	}

	var end docEnd
	switch assetType {
	case "Organization":
		for _, q := range []graph.OrganizationQuery{{Name: name}, {LegalName: name}} {
			res, err := r.g.ResolveOrganizations(r.ctx, q, 2)
			if err != nil {
				return end, err
			}
			if res.Status == "matched" && len(res.Candidates) == 1 {
				end = docEnd{asset: res.Candidates[0].Asset, ok: true}
				break
			}
			if res.Status == "ambiguous" || res.Status == "truncated" {
				break
			}
		}
	case "Person", "StreetAddress":
		field := "full_name"
		if assetType == "StreetAddress" {
			field = "address"
		}
		res, err := r.g.ResolveAsset(r.ctx, graph.AssetSelector{Type: assetType, Field: field, Value: name}, 2)
		// a type the repository cannot search by that field resolves to
		// nothing
		if err == nil && res.Status == "matched" && len(res.Candidates) == 1 {
			end = docEnd{asset: res.Candidates[0].Asset, ok: true}
		}
	}
	r.resolved[key] = end
	return end, nil
}

// isLinked reports whether the two assets are already linked by the label,
// or, for organizations, by org_unit or subsidiary in either direction, so a
// known link is not proposed again.
func (r *docRelations) isLinked(fromID, toID, label string) (bool, error) {
	labels := []string{label}
	if label == "org_unit" || label == "subsidiary" {
		labels = []string{"org_unit", "subsidiary"}
	}
	for _, l := range labels {
		key := fromID + "\x00" + l + "\x00" + toID
		if v, ok := r.linked[key]; ok {
			if v {
				return true, nil
			}
			continue
		}
		edges, err := r.g.Edges(r.ctx, fromID, "both", l, time.Time{})
		if err != nil {
			return false, err
		}
		found := false
		for _, e := range edges {
			if (e.FromID == fromID && e.ToID == toID) || (e.FromID == toID && e.ToID == fromID) {
				found = true
			}
		}
		r.linked[key] = found
		if found {
			return true, nil
		}
	}
	return false, nil
}
