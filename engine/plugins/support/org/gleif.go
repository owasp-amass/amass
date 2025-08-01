// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/adrg/strutil"
	"github.com/adrg/strutil/metrics"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
)

// GLEIFSearchFuzzyCompletions performs the fuzzy completion search for the given name.
func GLEIFSearchFuzzyCompletions(e *et.Event, orgent *dbt.Entity, name string) (*LEIRecord, error) {
	u := "https://api.gleif.org/api/v1/fuzzycompletions?field=entity.legalName&q=" + url.QueryEscape(name)

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
	if err != nil || resp.Body == "" {
		msg := fmt.Sprintf("Failed to obtain the LEI record for %s: %s", name, err)
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: %s", msg)
	}

	var result struct {
		Data []struct {
			Type       string `json:"type"`
			Attributes struct {
				Value string `json:"value"`
			} `json:"attributes"`
			Relationships struct {
				LEIRecords struct {
					Data struct {
						Type string `json:"type"`
						ID   string `json:"id"`
					} `json:"data"`
					Links struct {
						Related string `json:"related"`
					} `json:"links"`
				} `json:"lei-records"`
			} `json:"relationships"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		msg := fmt.Sprintf("Failed to unmarshal the LEI record for %s: %s", name, err)
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: %s", msg)
	} else if len(result.Data) == 0 {
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: no results found")
	}

	var names []string
	m := make(map[string]string)
	for _, d := range result.Data {
		if d.Type == "fuzzycompletions" && d.Relationships.LEIRecords.Data.Type == "lei-records" {
			names = append(names, d.Attributes.Value)
			m[d.Attributes.Value] = d.Relationships.LEIRecords.Data.ID
		}
	}

	var rec *LEIRecord
	if exact, partial, found := NameMatch(e.Session, orgent, names); found {
		var conf int

		for _, match := range exact {
			score := 30

			if len(exact) == 1 {
				score += 30
			}

			lei := m[match]
			if r, err := GLEIFGetLEIRecord(lei); err == nil {
				if locMatch(e, orgent, r) {
					score += 40
				}
				if score > conf {
					rec = r
					conf = score
				}
			}
		}

		swg := metrics.NewSmithWatermanGotoh()
		swg.CaseSensitive = false
		swg.GapPenalty = -0.1
		swg.Substitution = metrics.MatchMismatch{
			Match:    1,
			Mismatch: -0.5,
		}

		for _, match := range partial {
			if !strings.Contains(strings.ToLower(match), strings.ToLower(name)) {
				continue
			}

			sim := strutil.Similarity(name, match, swg)
			score := int(math.Round(sim * 30))

			if len(partial) == 1 {
				score += 30
			}

			lei := m[match]
			if r, err := GLEIFGetLEIRecord(lei); err == nil {
				if locMatch(e, orgent, r) {
					score += 40
				}
				if score > conf {
					rec = r
					conf = score
				}
			}
		}
	}

	if rec == nil {
		msg := fmt.Sprintf("Failed to find a matching LEI record for %s", name)
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: %w", errors.New(msg))
	}
	return rec, nil
}

// GLEIFGetLEIRecord retrieves the LEI record for the given identifier.
func GLEIFGetLEIRecord(id string) (*LEIRecord, error) {
	u := "https://api.gleif.org/api/v1/lei-records/" + id

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
	if err != nil || resp.StatusCode != 200 || resp.Body == "" {
		return nil, err
	}

	var result SingleResponse
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return nil, err
	} else if result.Data.Type != "lei-records" || result.Data.ID != id {
		return nil, errors.New("failed to find the LEI record")
	}
	return &result.Data, nil
}

// GLEIFGetDirectParentRecord retrieves the direct parent LEI record for the given identifier.
func GLEIFGetDirectParentRecord(id string) (*LEIRecord, error) {
	u := "https://api.gleif.org/api/v1/lei-records/" + id + "/direct-parent"

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
	if err != nil || resp.StatusCode != 200 || resp.Body == "" {
		return nil, err
	}

	var result SingleResponse
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return nil, err
	} else if result.Data.Type != "lei-records" {
		return nil, errors.New("failed to find the LEI record")
	}
	return &result.Data, nil
}

// GLEIFGetDirectChildrenRecords retrieves the direct children LEI records for the given identifier.
func GLEIFGetDirectChildrenRecords(id string) ([]*LEIRecord, error) {
	var children []*LEIRecord

	last := 1
	link := "https://api.gleif.org/api/v1/lei-records/" + id + "/direct-children"
	for i := 1; i <= last && link != ""; i++ {
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: link})
		if err != nil || resp.StatusCode != 200 || resp.Body == "" {
			return nil, err
		}

		var result MultipleResponse
		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
			return nil, err
		}

		for _, rec := range result.Data {
			children = append(children, &rec)
		}

		link = result.Links.Next
		last = result.Meta.Pagination.LastPage
	}

	return children, nil
}

// locMatch checks if the LEI record matches the location of the organization entity.
func locMatch(e *et.Event, orgent *dbt.Entity, rec *LEIRecord) bool {
	if rec == nil {
		return false
	}

	legal_addr := rec.Attributes.Entity.LegalAddress
	hq_addr := rec.Attributes.Entity.HeadquartersAddress
	if edges, err := e.Session.Cache().OutgoingEdges(orgent,
		time.Time{}, "legal_address", "hq_address", "location"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if loc, ok := a.Asset.(*contact.Location); ok {
					for _, p := range append([]LEIAddress{legal_addr, hq_addr}, rec.Attributes.Entity.OtherAddresses...) {
						if loc.PostalCode == p.PostalCode {
							return true
						}
					}
				}
			}
		}
	}

	var crs []*dbt.Entity
	if edges, err := e.Session.Cache().IncomingEdges(orgent, time.Time{}, "organization"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*contact.ContactRecord); ok {
					crs = append(crs, a)
				}
			}
		}
	}

	for _, cr := range crs {
		if edges, err := e.Session.Cache().OutgoingEdges(cr, time.Time{}, "location"); err == nil {
			for _, edge := range edges {
				if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
					if loc, ok := a.Asset.(*contact.Location); ok {
						for _, p := range append([]LEIAddress{legal_addr, hq_addr}, rec.Attributes.Entity.OtherAddresses...) {
							if loc.PostalCode == p.PostalCode {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}
