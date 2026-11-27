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

//go:embed fingerprint_defaults.json
var fingerprintDefaultsJSON []byte

type fingerprintDefault struct {
	IDType string `json:"id_type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

type fingerprintDefaults struct {
	License  string               `json:"_license"`
	About    string               `json:"_about"`
	Defaults []fingerprintDefault `json:"defaults"`
}

// loadFingerprintDefaults indexes the catalog as id_type -> set of normalized
// default values.
var loadFingerprintDefaults = sync.OnceValue(func() map[string]map[string]bool {
	var c fingerprintDefaults
	dec := json.NewDecoder(bytes.NewReader(fingerprintDefaultsJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("fingerprint_defaults.json: " + err.Error())
	}

	out := map[string]map[string]bool{}
	for _, d := range c.Defaults {
		if d.IDType == "" || d.Value == "" || !strings.HasPrefix(d.Source, "https://") {
			panic("fingerprint_defaults.json: each default needs an id_type, a value and an https source")
		}
		if out[d.IDType] == nil {
			out[d.IDType] = map[string]bool{}
		}
		out[d.IDType][normFingerprintValue(d.Value)] = true
	}

	return out
})

func normFingerprintValue(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// IsDefaultFingerprint reports whether value is a known default for id_type
// that ships with server or framework software and so carries no ownership
// signal. Collectors do not materialize such a value as a shared Identifier, so
// a generic value never becomes a hub in the shared database.
func IsDefaultFingerprint(idType, value string) bool {
	m := loadFingerprintDefaults()[idType]
	if m == nil {
		return false
	}

	return m[normFingerprintValue(value)]
}
