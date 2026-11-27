// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// propDocStatement is a statement the document model read from a document
// (see review.PropDocStatement).
const propDocStatement = "doc_statement"

// allEvidence reads every property of an asset (graph.Graph Evidence takes
// a count).
const allEvidence = math.MaxInt

// DocumentSource is one stored File the subject publishes, with where its
// bytes can be fetched again for the document model to read. The Asset
// Database keeps no copy of a document's content, only its metadata, the
// assets it names and its content hash.
type DocumentSource struct {
	FileID string `json:"file_id"`
	URL    string `json:"url"`
	// RetrievedFrom is the web archive copy the engine read, when it read
	// one instead of the URL itself.
	RetrievedFrom string `json:"retrieved_from,omitempty"`
	MediaType     string `json:"media_type,omitempty"`
	// SHA256 is the content hash of the version the engine stored.
	SHA256 string `json:"sha256,omitempty"`
	// Statements counts the statements already stored on the File.
	Statements int `json:"statements,omitempty"`
	// Dated is the newest date the document's own metadata states, zero when
	// it states none; Stale reports it older than DocumentStaleAge.
	Dated time.Time `json:"dated,omitzero"`
	Stale bool      `json:"stale,omitempty"`
}

// DocumentSources lists the Files stored from the URLs a domain or
// organization controls, in URL order. It reads only.
func DocumentSources(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) ([]DocumentSource, error) {
	out, _, err := documentSourcesOf(ctx, g, schema, root, limits)
	return out, err
}

// documentSourcesOf is DocumentSources, also returning the documents'
// publisher: root when it is an organization, otherwise the one organization
// that owns it (none when no organization, or more than one, does).
func documentSourcesOf(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) ([]DocumentSource, graph.Asset, error) {
	g = graph.Cached(g)
	s, err := newScope(ctx, g, schema, root, limits, LensDocuments)
	if err != nil {
		return nil, graph.Asset{}, err
	}
	var publisher graph.Asset
	switch {
	case root.Type == "Organization":
		publisher = root
	case len(s.owners) == 1:
		publisher = s.owners[0]
	}

	urls, err := s.ownedURLs()
	if err != nil {
		return nil, publisher, err
	}

	seen := map[string]bool{}
	var out []DocumentSource
	for _, u := range urls {
		if s.spent() {
			break
		}
		steps, err := s.w.steps(u)
		if err != nil {
			return out, publisher, err
		}
		for _, st := range steps {
			if !st.forward || st.other.Type != "File" || seen[st.other.ID] {
				continue
			}
			seen[st.other.ID] = true

			src, err := s.documentSource(st.other)
			if err != nil {
				return out, publisher, err
			}
			out = append(out, src)
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out, publisher, nil
}

// documentSource reads where a File came from and its content hash.
func (s *scope) documentSource(f graph.Asset) (DocumentSource, error) {
	src := DocumentSource{
		FileID:    f.ID,
		URL:       graph.ContentString(f, "url"),
		MediaType: graph.ContentString(f, "type"),
	}
	if src.URL == "" {
		src.URL = graph.AssetLabel(f)
	}

	ev, err := s.w.graph.Evidence(s.w.ctx, f.ID, allEvidence)
	if err != nil {
		return src, err
	}
	if from := firstValue(propertyValues(ev, propDocRetrievedFrom)); from != "" && from != src.URL {
		src.RetrievedFrom = from
	}
	src.Statements = len(propertyValues(ev, propDocStatement))
	src.Dated = documentDated(ev)
	src.Stale = StaleDocument(src.Dated, time.Now())

	steps, err := s.w.steps(f)
	if err != nil {
		return src, err
	}
	for _, st := range steps {
		if st.forward && st.edge.Label == "fingerprint" && graph.ContentString(st.other, "id_type") == "file_sha256" {
			src.SHA256 = graph.ContentString(st.other, "id")
		}
	}
	return src, nil
}
