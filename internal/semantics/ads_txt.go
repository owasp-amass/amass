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

//go:embed ads_txt.json
var adsTxtJSON []byte

// AdsTxt is how advertising seller accounts are read. Loaded from
// ads_txt.json; see that file's _about.
type AdsTxt struct {
	License         string   `json:"_license"`
	About           string   `json:"_about"`
	Files           []string `json:"files"`
	SellersPath     string   `json:"sellers_path"`
	Source          string   `json:"source"`
	SellersSource   string   `json:"sellers_source"`
	MaxFileBytes    int      `json:"max_file_bytes"`
	MaxAccounts     int      `json:"max_accounts"`
	MaxSellersBytes int64    `json:"max_sellers_bytes"`
	SellersTTLHours int      `json:"sellers_ttl_hours"`
}

var loadAdsTxt = sync.OnceValue(func() AdsTxt {
	var c AdsTxt
	dec := json.NewDecoder(bytes.NewReader(adsTxtJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("ads_txt.json: " + err.Error())
	}
	if len(c.Files) == 0 || !strings.HasPrefix(c.SellersPath, "/") || c.MaxFileBytes <= 0 || c.MaxAccounts <= 0 ||
		c.MaxSellersBytes <= 0 || c.SellersTTLHours <= 0 {
		panic("ads_txt.json: files, sellers_path, max_file_bytes, max_accounts, max_sellers_bytes and " +
			"sellers_ttl_hours are required")
	}
	return c
})

// AdsTxtCatalog returns the advertising seller catalog.
func AdsTxtCatalog() AdsTxt { return loadAdsTxt() }
