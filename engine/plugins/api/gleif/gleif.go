// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"golang.org/x/time/rate"
)

var gleifLimit *rate.Limiter

func init() {
	limit := rate.Every(3 * time.Second)

	gleifLimit = rate.NewLimiter(limit, 1)
}

// errNoResults is a search that found no LEI record, which is an answer and
// not a failure.
var errNoResults = errors.New("no results found")

// gleifGet fetches the GLEIF API URL within the rate limit and returns the
// body, or an error that says why there is none: the request failed, or the
// API answered with another status than 200 or with nothing.
func gleifGet(ctx context.Context, client *http.Client, u string) (string, error) {
	_ = support.WaitLimit(ctx, gleifLimit)
	wctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(wctx, client, &amasshttp.Request{URL: u})
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	if resp.Body == "" {
		return "", errors.New("empty answer")
	}
	return resp.Body, nil
}

// GLEIFSearchFuzzyCompletions performs the fuzzy completion search for the given name.
func GLEIFSearchFuzzyCompletions(ctx context.Context, client *http.Client, name string) (*FuzzyCompletionsResponse, error) {
	u := "https://api.gleif.org/api/v1/fuzzycompletions?field=entity.legalName&q=" + url.QueryEscape(name)

	body, err := gleifGet(ctx, client, u)
	if err != nil {
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: failed to search for %s: %w", name, err)
	}

	var result FuzzyCompletionsResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		msg := fmt.Sprintf("Failed to unmarshal the LEI record for %s: %s", name, err)
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: %s", msg)
	} else if len(result.Data) == 0 {
		return nil, fmt.Errorf("GLEIFSearchFuzzyCompletions: %w", errNoResults)
	}

	return &result, nil
}

// GLEIFSearchByAddress finds LEI records that mention the street and city,
// with a legal address in the country, so an address can be resolved to the
// organizations registered there. The register filters addresses only by
// country; the street and city go to its full-text search, which also matches
// other fields, so the caller confirms the street, number and city itself.
// The result is bounded to one page, and a country, street and city are all
// required so the search is never a whole country.
func GLEIFSearchByAddress(ctx context.Context, client *http.Client, street, city, country string) ([]*LEIRecord, error) {
	street, city, country = strings.TrimSpace(street), strings.TrimSpace(city), strings.TrimSpace(country)
	if street == "" || city == "" || country == "" {
		return nil, errors.New("GLEIFSearchByAddress: a street, city and country are required")
	}

	v := url.Values{}
	v.Set("filter[entity.legalAddress.country]", country)
	v.Set("filter[fulltext]", street+" "+city)
	v.Set("page[size]", "50")
	u := "https://api.gleif.org/api/v1/lei-records?" + v.Encode()

	body, err := gleifGet(ctx, client, u)
	if err != nil {
		return nil, fmt.Errorf("GLEIFSearchByAddress: failed to query the register: %w", err)
	}

	var result MultipleResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, fmt.Errorf("GLEIFSearchByAddress: %v", err)
	}

	out := make([]*LEIRecord, 0, len(result.Data))
	for i := range result.Data {
		out = append(out, &result.Data[i])
	}
	return out, nil
}

// GLEIFGetLEIRecord retrieves the LEI record for the given identifier.
func GLEIFGetLEIRecord(ctx context.Context, client *http.Client, id string) (*LEIRecord, error) {
	u := "https://api.gleif.org/api/v1/lei-records/" + id

	body, err := gleifGet(ctx, client, u)
	if err != nil {
		return nil, err
	}

	var result SingleResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, err
	} else if result.Data.Type != "lei-records" || result.Data.ID != id {
		return nil, errors.New("failed to find the LEI record")
	}
	return &result.Data, nil
}

// GLEIFGetDirectParentRecord retrieves the direct parent LEI record for the given identifier.
func GLEIFGetDirectParentRecord(ctx context.Context, client *http.Client, id string) (*LEIRecord, error) {
	u := "https://api.gleif.org/api/v1/lei-records/" + id + "/direct-parent"

	body, err := gleifGet(ctx, client, u)
	if err != nil {
		return nil, err
	}

	var result SingleResponse
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, err
	} else if result.Data.Type != "lei-records" {
		return nil, errors.New("failed to find the LEI record")
	}
	return &result.Data, nil
}

// GLEIFGetDirectChildrenRecords retrieves the direct children LEI records for the given identifier.
func GLEIFGetDirectChildrenRecords(ctx context.Context, client *http.Client, id string) ([]*LEIRecord, error) {
	var children []*LEIRecord

	last := 1
	link := "https://api.gleif.org/api/v1/lei-records/" + id + "/direct-children"
	for i := 1; i <= last && link != ""; i++ {
		body, err := gleifGet(ctx, client, link)
		if err != nil {
			return nil, err
		}

		var result MultipleResponse
		if err := json.Unmarshal([]byte(body), &result); err != nil {
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
