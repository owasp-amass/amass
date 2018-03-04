// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stringset

import (
	"sync"
)

type StringSet struct {
	sync.Mutex
	Set map[string]struct{}
}

func NewStringSet() *StringSet {
	return &StringSet{Set: make(map[string]struct{})}
}

func (ss *StringSet) Add(s string) {
	ss.Lock()
	defer ss.Unlock()

	ss.Set[s] = struct{}{}
}

func (ss *StringSet) AddAll(s []string) {
	for _, v := range s {
		ss.Add(v)
	}
}

func (ss *StringSet) Contains(s string) bool {
	ss.Lock()
	defer ss.Unlock()

	_, found := ss.Set[s]
	return found
}

func (ss *StringSet) ContainsAny(s []string) bool {
	for _, v := range s {
		if ss.Contains(v) {
			return true
		}
	}
	return false
}

func (ss *StringSet) ContainsAll(s []string) bool {
	for _, v := range s {
		if !ss.Contains(v) {
			return false
		}
	}
	return true
}

func (ss *StringSet) ToStrings() []string {
	var result []string

	ss.Lock()
	defer ss.Unlock()

	for k := range ss.Set {
		result = append(result, k)
	}

	return result
}

func (ss *StringSet) Equal(second *StringSet) bool {
	return ss.ContainsAll(second.ToStrings())
}

func (ss *StringSet) Empty() bool {
	if len(ss.ToStrings()) == 0 {
		return true
	}
	return false
}
