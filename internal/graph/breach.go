// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
	"sort"
)

// BreachProperty is the property name of a stored breach-exposure record: one
// known breach an email identifier appears in. Its value is a JSON-encoded
// BreachInfo, so one identifier carries one such property per breach. The
// value is metadata only — a breach name, date and the categories of data
// exposed — never a leaked secret.
const BreachProperty = "breach"

// BreachInfo is the metadata of one breach an identifier appears in.
type BreachInfo struct {
	Breach      string   `json:"breach"`
	Date        string   `json:"date,omitempty"`
	DataClasses []string `json:"classes,omitempty"`
	Source      string   `json:"source,omitempty"`
	Verified    bool     `json:"verified,omitempty"`
}

// EncodeBreach renders a breach record as the value of a breach property.
func EncodeBreach(b BreachInfo) (string, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// breachEvidence bounds how many of an identifier's properties are read when
// gathering its breach exposures.
const breachEvidence = 200

// BreachExposures returns the known breaches an identifier appears in, read
// from its stored breach properties, sorted by breach name. An empty result
// means none is stored.
func BreachExposures(ctx context.Context, g Graph, id string) ([]BreachInfo, error) {
	evidence, err := g.Evidence(ctx, id, breachEvidence)
	if err != nil {
		return nil, err
	}

	var out []BreachInfo
	for _, ev := range evidence {
		data, err := json.Marshal(ev.Property)
		if err != nil {
			continue
		}
		var p struct {
			Name  string `json:"property_name"`
			Value string `json:"property_value"`
		}
		if json.Unmarshal(data, &p) != nil || p.Name != BreachProperty || p.Value == "" {
			continue
		}
		var b BreachInfo
		if json.Unmarshal([]byte(p.Value), &b) != nil || b.Breach == "" {
			continue
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Breach < out[j].Breach })
	return out, nil
}
