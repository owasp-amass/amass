// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stringset

import "sync"

// StringFilter implements an object that performs filtering of strings
// to ensure that only unique items get through the filter.
type StringFilter struct {
	filter Set
	lock   sync.Mutex
}

// NewStringFilter returns an initialized StringFilter.
func NewStringFilter() *StringFilter {
	s := New()

	return &StringFilter{filter: s}
}

// Duplicate checks if the name provided has been seen before by this filter.
func (sf *StringFilter) Duplicate(s string) bool {
	sf.lock.Lock()
	defer sf.lock.Unlock()

	if sf.filter.Has(s) {
		return true
	}

	sf.filter.Insert(s)
	return false
}
