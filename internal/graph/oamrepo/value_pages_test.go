// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"strconv"
	"testing"

	dbt "github.com/owasp-amass/asset-db/types"
)

// A value search reads page after page, each after the last entity of the
// one before, until it has every match or the limit.
func TestValuePages(t *testing.T) {
	var all []*dbt.Entity
	for i := 1; i <= 1200; i++ {
		all = append(all, &dbt.Entity{ID: strconv.Itoa(i)})
	}
	var reads int
	read := func(after string, n int) ([]*dbt.Entity, bool, error) {
		reads++
		start := 0
		if after != "" {
			start, _ = strconv.Atoi(after)
		}
		end := min(start+n, len(all))
		return all[start:end], end < len(all), nil
	}

	ents, more, err := valuePages(0, read)
	if err != nil || more || len(ents) != 1200 || reads != 3 || ents[1199].ID != "1200" {
		t.Errorf("every match: %d entities, more %v, %d reads (%v)", len(ents), more, reads, err)
	}

	reads = 0
	ents, more, err = valuePages(51, read)
	if err != nil || !more || len(ents) != 51 || reads != 1 {
		t.Errorf("a limit of 51: %d entities, more %v, %d reads (%v)", len(ents), more, reads, err)
	}

	reads = 0
	ents, more, err = valuePages(700, read)
	if err != nil || !more || len(ents) != 700 || reads != 2 || ents[699].ID != "700" {
		t.Errorf("a limit past one page: %d entities, more %v, %d reads (%v)", len(ents), more, reads, err)
	}
}
