// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build windows

package utils

// GetFileLimit attempts to raise the ulimit to the maximum hard limit and returns that value.
func GetFileLimit() int {
	return 10000
}
