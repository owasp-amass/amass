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

//go:embed peeringdb.json
var peeringDBJSON []byte

// PeeringDB is how PeeringDB is read. Loaded from peeringdb.json; see that
// file's _about.
type PeeringDB struct {
	License        string `json:"_license"`
	About          string `json:"_about"`
	Source         string `json:"source"`
	API            string `json:"api"`
	NetPath        string `json:"net_path"`
	OrgPath        string `json:"org_path"`
	PageURL        string `json:"page_url"`
	RequestSeconds int    `json:"request_seconds"`
	MaxNetworks    int    `json:"max_networks"`
}

var loadPeeringDB = sync.OnceValue(func() PeeringDB {
	var c PeeringDB
	dec := json.NewDecoder(bytes.NewReader(peeringDBJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("peeringdb.json: " + err.Error())
	}
	if !strings.HasPrefix(c.API, "https://") || !strings.HasPrefix(c.NetPath, "/") ||
		!strings.HasPrefix(c.OrgPath, "/") || !strings.HasPrefix(c.PageURL, "https://") ||
		c.RequestSeconds <= 0 || c.MaxNetworks <= 0 {
		panic("peeringdb.json: api, net_path, org_path, page_url, request_seconds and max_networks are required")
	}
	return c
})

// PeeringDBCatalog returns how PeeringDB is read.
func PeeringDBCatalog() PeeringDB { return loadPeeringDB() }
