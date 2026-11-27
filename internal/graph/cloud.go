// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"encoding/json"
)

const (
	// CloudRegionProperty is the property name of a netblock's cloud region,
	// as its provider's range feed publishes it (for example us-east-1).
	CloudRegionProperty = "cloud_region"
	// CloudServiceProperty is the property name of a netblock's cloud
	// service, as its provider's range feed publishes it (for example S3).
	CloudServiceProperty = "cloud_service"
)

// cloudMetaEvidence bounds how many of a netblock's properties are read when
// gathering its cloud region and service.
const cloudMetaEvidence = 50

// CloudMeta returns the cloud region and service a provider's range feed
// published for a netblock, read from its stored properties. Either is empty
// when none is stored.
func CloudMeta(ctx context.Context, g Graph, id string) (region, service string) {
	evidence, err := g.Evidence(ctx, id, cloudMetaEvidence)
	if err != nil {
		return "", ""
	}

	for _, ev := range evidence {
		data, err := json.Marshal(ev.Property)
		if err != nil {
			continue
		}
		var p struct {
			Name  string `json:"property_name"`
			Value string `json:"property_value"`
		}
		if json.Unmarshal(data, &p) != nil || p.Value == "" {
			continue
		}
		switch p.Name {
		case CloudRegionProperty:
			region = p.Value
		case CloudServiceProperty:
			service = p.Value
		}
	}
	return region, service
}
