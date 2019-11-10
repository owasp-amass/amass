// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"github.com/OWASP/Amass/v3/graph/db"
)

// InsertNetblock adds a netblock/CIDR to the graph.
func (g *Graph) InsertNetblock(cidr, source, tag, eventID string) (db.Node, error) {
	cidrNode, err := g.InsertNodeIfNotExist(cidr, "netblock")
	if err != nil {
		return cidrNode, err
	}

	if err := g.AddNodeToEvent(cidrNode, source, tag, eventID); err != nil {
		return cidrNode, err
	}

	return cidrNode, nil
}
