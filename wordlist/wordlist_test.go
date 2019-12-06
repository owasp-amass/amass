// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package wordlist

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestExpandMask(t *testing.T) {
	tests := []struct {
		name     string
		event    string
		expected int
	}{

		{"Test 1: All", "test?a", 37},
		{"Test 2: Letter (?l)", "test?l", 26},
		{"Test 3: Letter (?u)", "test?u", 26},
		{"Test 4: Digit", "test?d", 10},
		{"Test 5: Special", "test?s", 1},
		{"Test 6: Multiple All", "test?a?a", 1369},
		{"Test 7: Multiple Letters (?l)", "test?l?l", 676},
		{"Test 8: Multiple Letters (?u)", "test?u?u", 676},
		{"Test 9: Multiple Digits", "test?d?d", 100},
		{"Test 10: Multiple Special", "test?s?s", 1},
		{"Test 11: Mixed Mask", "test?a?l?d", 9620},
		{"Test 12: Mask too long", "test?a?a?a?a?a", 0},
		{"Test 13: No Mask", "test", 1},
		{"Test 14: Bad Mask", "?#", 0},
		{"Test 15: Worse Mask", "?a?^", 0},
	}

	for _, tt := range tests {
		s, _ := ExpandMask(tt.event)
		if len(s) != tt.expected {
			t.Errorf("Error Event %s: was expecting %d, got %d", tt.name, tt.expected, len(s))
		}
	}
}

func TestExpandMaskWordlist(t *testing.T) {
	tests := []struct {
		name     string
		event    []string
		expected int
	}{

		{"Test 1: Wordlist", []string{"?a", "?d", "?u", "?l", "?s", "none", "none2", "?#", "?a?%"}, 102},
	}
	for _, tt := range tests {
		s, _ := ExpandMaskWordlist(tt.event)

		if len(s) != tt.expected {
			t.Errorf("Error Event %s: was expecting %d, got %d", tt.name, tt.expected, len(s))
		}
	}
}

func TestWordList(t *testing.T) {
	want := []string{"TestReader"}
	r := strings.NewReader(want[0])
	got := getWordList(r)

	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Expected %v, got %v", want, got)
	}

}
