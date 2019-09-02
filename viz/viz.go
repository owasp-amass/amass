// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package viz

// Edge represents an Amass graph edge throughout the viz package.
type Edge struct {
	From, To int
	Label    string
	Title    string
}

// Node represents an Amass graph node throughout the viz package.
type Node struct {
	ID     int
	Type   string
	Label  string
	Title  string
	Source string
}
