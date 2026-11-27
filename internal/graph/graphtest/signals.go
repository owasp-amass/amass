// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"github.com/owasp-amass/amass/v5/internal/graph"
)

func TXTRecord(data string) graph.Evidence {
	return graph.Evidence{Kind: "DNSRecordProperty", Property: map[string]any{"property_name": "dns_record",
		"header": map[string]any{"rr_type": graph.RRTypeTXT, "class": 1}, "data": data}}
}

// CAARecord builds an Evidence entry for a stored CAA record, its data
// rendered as `<flags> <tag> "<value>"`.
func CAARecord(data string) graph.Evidence {
	return graph.Evidence{Kind: "DNSRecordProperty", Property: map[string]any{"property_name": "dns_record",
		"header": map[string]any{"rr_type": graph.RRTypeCAA, "class": 1}, "data": data}}
}

// SimpleProp builds an Evidence entry for a stored general.SimpleProperty.
func SimpleProp(name, value string) graph.Evidence {
	return graph.Evidence{Kind: "SimpleProperty",
		Property: map[string]any{"property_name": name, "property_value": value}}
}
