// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed hubs.json
var hubsJSON []byte

// Hubs is how hub limits are derived from the database's data. Loaded from
// hubs.json; see that file's _about.
type Hubs struct {
	License      string  `json:"_license"`
	About        string  `json:"_about"`
	K            float64 `json:"k"`
	MinSample    int64   `json:"min_sample"`
	Floor        int     `json:"floor"`
	RefreshHours int     `json:"refresh_hours"`
}

var loadHubs = sync.OnceValue(func() Hubs {
	var c Hubs
	dec := json.NewDecoder(bytes.NewReader(hubsJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("hubs.json: " + err.Error())
	}
	if c.K <= 0 || c.MinSample <= 0 || c.Floor <= 0 || c.RefreshHours <= 0 {
		panic("hubs.json: k, min_sample, floor and refresh_hours must be positive")
	}
	return c
})

// HubsCatalog returns the hub derivation settings.
func HubsCatalog() Hubs { return loadHubs() }
