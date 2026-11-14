// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
	"strings"
)

const (
	// dnsRecordProperty is the property name of stored DNS records.
	DNSRecordProperty = "dns_record"
)

const (
	RRTypeTXT = 16
)

// txtValues returns the TXT record values stored for an asset.
func TXTValues(ctx context.Context, graph Graph, id string) ([]string, error) {
	evidence, err := graph.Evidence(ctx, id, 100)
	if err != nil {
		return nil, err
	}

	var out []string
	for _, e := range evidence {
		data, err := json.Marshal(e.Property)
		if err != nil {
			continue
		}

		var p struct {
			Name   string `json:"property_name"`
			Header struct {
				RRType int `json:"rr_type"`
			} `json:"header"`
			Data string `json:"data"`
		}
		if json.Unmarshal(data, &p) == nil && p.Name == DNSRecordProperty && p.Header.RRType == RRTypeTXT &&
			p.Data != "" {
			out = append(out, strings.Trim(p.Data, `"`))
		}
	}

	return out, nil
}
