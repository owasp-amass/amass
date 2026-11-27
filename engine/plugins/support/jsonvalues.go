// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"encoding/json"
	"strconv"
	"strings"
)

// JSONStrings returns the string values of a JSON field whatever shape a
// source API gives it: a string, a number, a list, or an object such as a
// language-keyed map, read recursively. Object values come in no fixed order.
func JSONStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}

	var s string
	if json.Unmarshal(raw, &s) == nil {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	var num json.Number
	if json.Unmarshal(raw, &num) == nil {
		return []string{num.String()}
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		var out []string
		for _, item := range list {
			out = append(out, JSONStrings(item)...)
		}
		return out
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		var out []string
		for _, v := range obj {
			out = append(out, JSONStrings(v)...)
		}
		return out
	}
	return nil
}

// JSONString returns the first non-blank string value of a JSON field of any
// shape (JSONStrings), or "".
func JSONString(raw json.RawMessage) string {
	for _, s := range JSONStrings(raw) {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// JSONNumber returns the first positive number in a JSON field of any shape,
// a number or a numeric string (JSONStrings), or 0. Amounts and counts are
// what source APIs give this way, so zero and negative values are skipped.
func JSONNumber(raw json.RawMessage) float64 {
	for _, s := range JSONStrings(raw) {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && v > 0 {
			return v
		}
	}
	return 0
}
