// Copyright © by Jeff Foley 2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"strconv"
	"strings"
	"testing"
)

func TestFQDNFilterInsert(t *testing.T) {
	ff := NewFQDNFilter()
	defer ff.Close()

	fqdn := "www.cs.utica.edu"
	ff.Insert(fqdn)

	cur := ff
	labels := strings.Split(fqdn, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		if _, found := cur[labels[i]]; !found {
			t.Errorf("Passive DNS Filter Insert failed for label %s at index %d", labels[i], i)
			break
		}
		if i > 0 {
			cur = cur[labels[i]].(FQDNFilter)
		}
	}
}

func TestFQDNFilterPrune(t *testing.T) {
	ff := NewFQDNFilter()
	defer ff.Close()

	limit := 50
	for i := 0; i < limit; i++ {
		fqdn := "www" + strconv.Itoa(i) + ".cs.utica.edu"
		ff.Insert(fqdn)
	}

	var found bool
	var name string
	ff.Prune(limit)
	for _, fqdn := range ff.Slice() {
		if fqdn == "www1.cs.utica.edu" {
			name = fqdn
			found = true
			break
		}
	}

	if found {
		t.Errorf("Passive DNS Filter Prune failed to remove the labels: %s", name)
	}
}

func TestFQDNFilterSlice(t *testing.T) {
	ff := NewFQDNFilter()
	defer ff.Close()

	fqdn := "www.cs.utica.edu"
	ff.Insert(fqdn)

	if fqdn != ff.Slice()[0] {
		t.Errorf("Passive DNS Filter Slice failed to produce the expected FQDN: %s", fqdn)
	}
}
