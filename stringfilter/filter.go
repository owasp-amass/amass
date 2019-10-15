// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stringfilter

import "github.com/thetannerryan/ring"

// StringFilter implements an object that performs filtering of strings
// to ensure that only unique items get through the filter.
type StringFilter struct {
	filter *ring.Ring
}

// NewStringFilter returns an initialized StringFilter.
func NewStringFilter() *StringFilter {
	r, err := ring.Init(1000000, 0.001)
	if err != nil {
		return nil
	}

	return &StringFilter{filter: r}
}

// Duplicate checks if the name provided has been seen before by this filter.
func (sf *StringFilter) Duplicate(s string) bool {
	if sf.filter.Test([]byte(s)) {
		return true
	}

	sf.filter.Add([]byte(s))
	return false
}
