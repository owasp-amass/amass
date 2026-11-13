// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
)

// Scores for an LEI record found by a name search. A record is accepted
// only when its name is the organization's (after legal forms and a
// leading article are removed) and a postal code or the country agrees. A
// postal code alone is not enough: a company's subsidiaries and retirement
// plans are registered at its own address under longer names (Google
// Energy LLC, Microsoft Corporation Savings Plus 401(k) Plan). A record in
// a country the organization's own locations contradict, or a fund, is
// never accepted.
const (
	nameScore     = 30
	uniqueScore   = 30
	postalScore   = 40
	countryScore  = 20
	maxMatchScore = 100
)

// locEvidence is what an organization's stored locations say about where
// it is: its own locations and those of its contact records.
type locEvidence struct {
	postal    map[string]bool
	countries map[string]bool
}

// leiCandidate is one LEI record a name search returned.
type leiCandidate struct {
	name  string
	rec   *LEIRecord
	exact bool
	// sim is the name similarity in [0, 1], for a partial match.
	sim    float64
	unique bool
}

// chooseLEIRecord returns the best candidate the organization's evidence
// supports, with its confidence, or nil when none is supported. brands
// are the organization's names reduced to brand form.
func chooseLEIRecord(brands []string, ev locEvidence, cands []leiCandidate) (*LEIRecord, int) {
	var best *LEIRecord
	var bestScore int
	for _, c := range cands {
		if c.rec == nil {
			continue
		}

		if strings.EqualFold(c.rec.Attributes.Entity.Category, "FUND") {
			// A fund or plan is never the organization itself.
			continue
		}

		countries := recordCountries(c.rec)
		if len(ev.countries) > 0 && !intersects(ev.countries, countries) {
			// The organization's own locations place it elsewhere.
			continue
		}

		postal := intersects(ev.postal, recordPostalCodes(c.rec))
		country := intersects(ev.countries, countries)
		equivalent := c.exact || sameBrand(brands, c.name)
		if !equivalent || (!postal && !country) {
			continue
		}

		score := int(math.Round(c.sim * nameScore))
		if equivalent {
			score = nameScore
		}
		if c.unique {
			score += uniqueScore
		}
		if postal {
			score += postalScore
		}
		if country {
			score += countryScore
		}
		score = min(score, maxMatchScore)
		if score > bestScore {
			best, bestScore = c.rec, score
		}
	}

	return best, bestScore
}

// brandForm reduces an organization name to its brand: lowercase, without
// a legal form suffix or trailing punctuation.
func brandForm(name string) string {
	b := org.ExtractBrandName(strings.ToLower(strings.TrimSpace(name)))
	b = strings.TrimRight(strings.TrimSpace(b), ".,")
	return strings.TrimSpace(strings.TrimPrefix(b, "the "))
}

func sameBrand(brands []string, name string) bool {
	b := brandForm(name)
	if b == "" {
		return false
	}
	for _, have := range brands {
		if have == b {
			return true
		}
	}

	return false
}

// recordCountries returns the alpha-2 countries of a record's addresses
// and jurisdiction.
func recordCountries(rec *LEIRecord) map[string]bool {
	ent := rec.Attributes.Entity
	out := map[string]bool{}
	for _, a := range append([]LEIAddress{ent.LegalAddress, ent.HeadquartersAddress}, ent.OtherAddresses...) {
		if c := normCountry(a.Country); c != "" {
			out[c] = true
		}
	}

	if j, _, _ := strings.Cut(ent.Jurisdiction, "-"); j != "" {
		if c := normCountry(j); c != "" {
			out[c] = true
		}
	}

	return out
}

func recordPostalCodes(rec *LEIRecord) map[string]bool {
	ent := rec.Attributes.Entity
	out := map[string]bool{}
	for _, a := range append([]LEIAddress{ent.LegalAddress, ent.HeadquartersAddress}, ent.OtherAddresses...) {
		if p := normPostal(a.PostalCode); p != "" {
			out[p] = true
		}
	}

	return out
}

func normCountry(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return ""
	}

	return strings.ToUpper(support.CountryToAlpha2Code(c))
}

func normPostal(p string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(p), " ", ""))
}

func intersects(a, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}

	return false
}

func (ev *locEvidence) add(loc *contact.Location) {
	if p := normPostal(loc.PostalCode); p != "" {
		ev.postal[p] = true
	}
	if c := normCountry(loc.Country); c != "" {
		ev.countries[c] = true
	}
}

// orgLocEvidence collects the postal codes and countries of the
// organization's locations and of its contact records' locations.
func orgLocEvidence(e *et.Event, orgent *dbt.Entity) locEvidence {
	ev := locEvidence{postal: map[string]bool{}, countries: map[string]bool{}}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 2*time.Minute)
	defer cancel()

	db := e.Session.DB()
	addLocations := func(from *dbt.Entity, labels ...string) {
		edges, err := db.OutgoingEdges(ctx, from, time.Time{}, labels...)
		if err != nil {
			return
		}
		for _, edge := range edges {
			if a, err := db.FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if loc, ok := a.Asset.(*contact.Location); ok {
					ev.add(loc)
				}
			}
		}
	}

	addLocations(orgent, "legal_address", "hq_address", "location")
	if edges, err := db.IncomingEdges(ctx, orgent, time.Time{}, "organization"); err == nil {
		for _, edge := range edges {
			if a, err := db.FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*contact.ContactRecord); ok {
					addLocations(a, "location")
				}
			}
		}
	}

	return ev
}
