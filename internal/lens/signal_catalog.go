// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// The signal catalog defines each kind of evidence that ties an asset to an
// organization once, with what it means for each question it answers (its
// uses): whether the organization owns an asset (UseOwnedAsset, the
// ownership-gap lens and automatic attribution) and whether another domain is
// the organization's (UseRelatedDomain, horizontal correlation and scope
// expansion). The same evidence can weigh differently for the two.
var signalsJSON = semantics.File("signals.json")

// Signal uses.
const (
	UseOwnedAsset    = "owned-asset"
	UseRelatedDomain = "related-domain"
)

// signalUse is what a signal means for one question.
type signalUse struct {
	Kind               string       `json:"kind"`
	Strength           string       `json:"strength"`
	Weight             float64      `json:"weight"`
	Tiebreaker         bool         `json:"tiebreaker,omitempty"`
	Matcher            string       `json:"matcher"`
	Params             SignalParams `json:"params,omitzero"`
	Finds              string       `json:"finds"`
	Rationale          string       `json:"rationale"`
	Guards             []string     `json:"guards"`
	CounterIndications []string     `json:"counter_indications"`
}

type catalogSignal struct {
	ID    string               `json:"id"`
	Title string               `json:"title"`
	Uses  map[string]signalUse `json:"uses"`
}

type signalFile struct {
	License string          `json:"_license"`
	About   string          `json:"_about"`
	Signals []catalogSignal `json:"signals"`
}

// signalID is the form of a catalog ID: lowercase words joined by hyphens.
var signalID = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

var loadSignalFile = sync.OnceValues(func() (signalFile, error) {
	var f signalFile
	if err := graph.DecodeStrict(signalsJSON, &f); err != nil {
		return f, fmt.Errorf("signals.json: %w", err)
	}

	seen := map[string]bool{}
	for _, s := range f.Signals {
		switch {
		case !signalID.MatchString(s.ID) || seen[s.ID]:
			return f, fmt.Errorf("signals.json: signal %q: missing, repeated or not hyphenated", s.ID)
		case s.Title == "" || len(s.Uses) == 0:
			return f, fmt.Errorf("signals.json: signal %s: title and uses are required", s.ID)
		}
		for use := range s.Uses {
			if use != UseOwnedAsset && use != UseRelatedDomain {
				return f, fmt.Errorf("signals.json: signal %s: unknown use %q", s.ID, use)
			}
		}
		seen[s.ID] = true
	}
	return f, nil
})

// signalView is the catalog as seen for one use: the signals that have it, in
// catalog order, each with that use's meaning.
func signalView(use string) (signalCatalog, error) {
	f, err := loadSignalFile()
	if err != nil {
		return signalCatalog{}, err
	}

	c := signalCatalog{License: f.License, About: f.About}
	for _, s := range f.Signals {
		u, ok := s.Uses[use]
		if !ok {
			continue
		}
		c.Signals = append(c.Signals, OwnershipSignal{ID: s.ID, Title: s.Title, Kind: u.Kind, Strength: u.Strength,
			Weight: u.Weight, Tiebreaker: u.Tiebreaker, Matcher: u.Matcher, Params: u.Params, Finds: u.Finds,
			Rationale: u.Rationale, Guards: u.Guards, CounterIndications: u.CounterIndications})
	}
	return c, nil
}

// signalUses returns the uses a signal has, for the documentation's notes on
// a signal's other use.
func signalUses(id string) map[string]bool {
	f, err := loadSignalFile()
	if err != nil {
		return nil
	}
	for _, s := range f.Signals {
		if s.ID == id {
			out := map[string]bool{}
			for u := range s.Uses {
				out[u] = true
			}
			return out
		}
	}
	return nil
}
