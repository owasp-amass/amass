// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"reflect"
	"strings"
)

type FQDNFilter map[string]interface{}

func NewFQDNFilter() FQDNFilter {
	return make(FQDNFilter)
}

func (r FQDNFilter) Insert(fqdn string) {
	parts := strings.Split(fqdn, ".")

	var labels []string
	for i := len(parts) - 1; i >= 0; i-- {
		labels = append(labels, parts[i])
	}

	cur := r
	llen := len(labels)
	for i, label := range labels {
		if e, found := cur[label]; !found && i < llen-1 {
			cur[label] = make(FQDNFilter)
			cur = cur[label].(FQDNFilter)
		} else if found && i < llen-1 {
			if reflect.TypeOf(e).Kind() == reflect.Struct {
				cur[label] = make(FQDNFilter)
			}
			cur = cur[label].(FQDNFilter)
		} else if !found && i == llen-1 {
			cur[label] = struct{}{}
		}
	}
}

func (r FQDNFilter) Prune(limit int) {
	for k, v := range r {
		switch t := v.(type) {
		case FQDNFilter:
			if len(t) >= limit {
				delete(r, k)
				r[k] = struct{}{}
			} else {
				t.Prune(limit)
			}
		}
	}
}

func (r FQDNFilter) Slice() []string {
	return r.processMap("")
}

func (r FQDNFilter) processMap(prefix string) []string {
	var fqdns []string

	for k, v := range r {
		name := k
		if prefix != "" {
			name += "." + prefix
		}

		switch t := v.(type) {
		case FQDNFilter:
			fqdns = append(fqdns, t.processMap(name)...)
		default:
			fqdns = append(fqdns, name)
		}
	}

	return fqdns
}

func (r FQDNFilter) Close() {
	for k := range r {
		delete(r, k)
	}
}
