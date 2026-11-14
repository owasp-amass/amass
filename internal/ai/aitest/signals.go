// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aitest

import (
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

func TXTRecord(data string) graph.Evidence {
	return graph.Evidence{Kind: "DNSRecordProperty", Property: map[string]any{"property_name": "dns_record",
		"header": map[string]any{"rr_type": graph.RRTypeTXT, "class": 1}, "data": data}}
}
