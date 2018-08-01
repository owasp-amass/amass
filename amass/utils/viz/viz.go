// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package viz

type Edge struct {
	From, To int
	Label    string
	Title    string
}

type Node struct {
	ID     int
	Type   string
	Label  string
	Title  string
	Source string
}
