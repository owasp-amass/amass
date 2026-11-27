// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package viz draws an organization's footprint for the visualize tool: the
// controlled-assets lens's assets and witness relations as nodes and edges,
// written as an interactive D3 page, a GEXF file or a Mermaid diagram.
package viz

// Edge is a relation between two nodes of a drawing.
type Edge struct {
	From, To int
	Label    string
	Title    string
}

// Node is an asset in a drawing.
type Node struct {
	ID    int
	Type  string
	Label string
	Title string
}
