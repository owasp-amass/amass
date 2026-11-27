// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"slices"
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
)

func TestShufflePortsKeepsEveryPort(t *testing.T) {
	ports := []int{21, 22, 25, 80, 110, 143, 443, 587, 993, 8080, 8443}

	got := ShufflePorts(ports)
	if len(got) != len(ports) {
		t.Fatalf("shuffled %d ports into %d", len(ports), len(got))
	}

	sorted := slices.Clone(got)
	slices.Sort(sorted)
	want := slices.Clone(ports)
	slices.Sort(want)
	if !slices.Equal(sorted, want) {
		t.Errorf("the shuffle changed the set of ports: %v", got)
	}

	// The input must not be modified.
	if !slices.IsSorted(ports) {
		t.Errorf("the input slice was reordered: %v", ports)
	}
}

func TestShufflePortsVariesOrder(t *testing.T) {
	ports := make([]int, 64)
	for i := range ports {
		ports[i] = 1000 + i
	}

	// Across several shuffles of 64 ports, at least one should differ from
	// the input order; all identical would mean no shuffling.
	for range 8 {
		if !slices.Equal(ShufflePorts(ports), ports) {
			return
		}
	}

	t.Error("ShufflePorts never changed the order of 64 ports")
}

func TestPaceProbeWithoutSessionIsNoOp(t *testing.T) {
	if err := PaceProbe(nil, "192.0.2.1"); err != nil {
		t.Errorf("a nil event should not pace or error: %v", err)
	}
	if err := PaceProbe(&et.Event{}, "192.0.2.1"); err != nil {
		t.Errorf("an event without a session should not pace or error: %v", err)
	}
}
