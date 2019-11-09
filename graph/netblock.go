// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

// InsertNetblock adds a netblock/CIDR to the graph.
func (g *Graph) InsertNetblock(cidr, source, tag, eventID string) error {
	cidrNode, err := g.db.ReadNode(cidr)
	if err != nil {
		cidrNode, err = g.db.InsertNode(cidr, "netblock")
		if err != nil {
			return err
		}
	}

	if err := g.AddNodeToEvent(cidrNode, source, tag, eventID); err != nil {
		return err
	}

	return nil
}
