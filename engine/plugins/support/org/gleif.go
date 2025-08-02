// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	"golang.org/x/time/rate"
)

var gleifLimit *rate.Limiter

func init() {
	limit := rate.Every(3 * time.Second)

	gleifLimit = rate.NewLimiter(limit, 1)
}

// GLEIFSearchFuzzyCompletions performs the fuzzy completion search for the given name.
func GLEIFSearchFuzzyCompletions(name string) (*FuzzyCompletionsResponse, error) {
	u := "https://api.gleif.org/api/v1/fuzzycompletions?field=entity.legalName&q=" + url.QueryEscape(name)

	_ = gleifLimit.Wait(context.TODO())
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
	if err != nil || resp.Body == "" {
		msg := fmt.Sprintf("Failed to obtain the LEI record for %s: %s", name, err)
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: %s", msg)
	}

	var result FuzzyCompletionsResponse
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		msg := fmt.Sprintf("Failed to unmarshal the LEI record for %s: %s", name, err)
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: %s", msg)
	} else if len(result.Data) == 0 {
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: no results found")
	}

	return &result, nil
}

// GLEIFGetLEIRecord retrieves the LEI record for the given identifier.
func GLEIFGetLEIRecord(id string) (*LEIRecord, error) {
	u := "https://api.gleif.org/api/v1/lei-records/" + id

	_ = gleifLimit.Wait(context.TODO())
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

	_ = gleifLimit.Wait(context.TODO())
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
		_ = gleifLimit.Wait(context.TODO())

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

// LocMatch checks if the LEI record matches the location of the organization entity.
func LocMatch(e *et.Event, orgent *dbt.Entity, rec *LEIRecord) bool {
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
