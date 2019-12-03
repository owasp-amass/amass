// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build windows

package limits

func TestGetFileLimit(t *testing.T) {
	if r := GetFileLimit(); r <= 0 {
		t.Errorf("Returned a non-positive limit")
	}
}
