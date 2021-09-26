// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package filter

import (
	"github.com/AndreasBriese/bbloom"
	"github.com/caffix/stringset"
)

// Filter is the object type for performing string filtering.
type Filter interface {
	// Duplicate checks if the name provided has been seen before by this filter.
	// If not, the string is added to the filter.
	Duplicate(s string) bool

	// Has returns true if the receiver StringFilter already contains the string argument.
	Has(s string) bool

	// Release resources allocated by the filter.
	Close()
}

// StringFilter implements the Filter interface using a Set
// so that only unique items get through the filter.
type StringFilter struct {
	filter *stringset.Set
}

// NewStringFilter returns an initialized StringFilter.
func NewStringFilter() *StringFilter {
	return &StringFilter{filter: stringset.New()}
}

// Close implements the Filter interface.
func (r *StringFilter) Close() {
	r.filter.Close()
}

// Duplicate implements the Filter interface.
func (r *StringFilter) Duplicate(s string) bool {
	found := r.filter.Has(s)

	if !found {
		r.filter.Insert(s)
	}

	return found
}

// Has implements the Filter interface.
func (r *StringFilter) Has(s string) bool {
	return r.filter.Has(s)
}

// BloomFilter implements the Filter interface using a bloom filter
// so that mostly unique items get through the filter.
type BloomFilter struct {
	filter bbloom.Bloom
}

// NewBloomFilter returns an initialized BloomFilter.
func NewBloomFilter(num int64) *BloomFilter {
	b := bbloom.New(float64(num), float64(0.01))

	return &BloomFilter{filter: b}
}

// Close implements the Filter interface.
func (r *BloomFilter) Close() {}

// Duplicate implements the Filter interface.
func (r *BloomFilter) Duplicate(s string) bool {
	added := r.filter.AddIfNotHasTS([]byte(s))

	return !added
}

// Has implements the Filter interface.
func (r *BloomFilter) Has(s string) bool {
	return r.filter.HasTS([]byte(s))
}
