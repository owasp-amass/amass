// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed reputation_feeds.json
var reputationFeedsJSON []byte

// ReputationListingProperty is the property a listed asset gets: the
// feed's name.
const ReputationListingProperty = "reputation_listing"

// Reputation feed formats.
const (
	FeedNDJSONCIDR = "ndjson_cidr"
	FeedLines      = "lines"
)

// ReputationFeed is one keyless reputation feed.
type ReputationFeed struct {
	Name         string `json:"name"`
	Title        string `json:"title"`
	URL          string `json:"url"`
	Format       string `json:"format"`
	RefreshHours int    `json:"refresh_hours"`
	Source       string `json:"source"`
}

// ReputationFeeds is the reputation feed catalog. Loaded from
// reputation_feeds.json; see that file's _about.
type ReputationFeeds struct {
	License  string           `json:"_license"`
	About    string           `json:"_about"`
	Feeds    []ReputationFeed `json:"feeds"`
	MaxBytes int64            `json:"max_bytes"`
}

var loadReputationFeeds = sync.OnceValue(func() ReputationFeeds {
	var c ReputationFeeds
	dec := json.NewDecoder(bytes.NewReader(reputationFeedsJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("reputation_feeds.json: " + err.Error())
	}
	if len(c.Feeds) == 0 || c.MaxBytes <= 0 {
		panic("reputation_feeds.json: feeds and max_bytes are required")
	}
	for _, f := range c.Feeds {
		if f.Name == "" || f.Title == "" || !strings.HasPrefix(f.URL, "https://") || f.RefreshHours <= 0 ||
			f.Source == "" || (f.Format != FeedNDJSONCIDR && f.Format != FeedLines) {
			panic("reputation_feeds.json: feed " + f.Name + " needs a name, title, https url, refresh_hours, " +
				"source and a known format")
		}
	}
	return c
})

// ReputationFeedCatalog returns the reputation feed catalog.
func ReputationFeedCatalog() ReputationFeeds { return loadReputationFeeds() }

// ReputationFeedTitles returns each feed name's title.
func ReputationFeedTitles() map[string]string {
	out := map[string]string{}
	for _, f := range loadReputationFeeds().Feeds {
		out[f.Name] = f.Title
	}
	return out
}
