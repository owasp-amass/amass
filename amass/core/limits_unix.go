// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd

package core

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// GetFileLimit raises the number of open files limit to the current hard limit. The
// value returned is equal to the new limit
func GetFileLimit() int {
	var lim syscall.Rlimit

	limit := 100000
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		lim.Cur = lim.Max
		if lim.Cur == unix.RLIM_INFINITY || lim.Cur > 100000 {
			lim.Cur = 100000
		}
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		limit = int(lim.Cur)
	}
	return limit
}
