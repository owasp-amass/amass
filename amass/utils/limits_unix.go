// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd

package utils

import (
	"syscall"
)

// GetFileLimit attempts to raise the ulimit to the maximum hard limit and returns that value.
func GetFileLimit() int {
	limit := 10000
	var lim syscall.Rlimit

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		lim.Cur = lim.Max
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil && lim.Cur != syscall.RLIM_INFINITY {
		limit = int(lim.Cur)
	}
	return limit
}
