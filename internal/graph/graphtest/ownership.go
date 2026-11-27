// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"github.com/owasp-amass/amass/v5/internal/graph"
)

func Asset(id, typ, key string) graph.Asset { return graph.Asset{ID: id, Type: typ, Key: key} }

func Edge(id, from, to, label string) graph.Relation {
	return graph.Relation{ID: id, FromID: from, ToID: to, Label: label, Type: "SimpleRelation"}
}
