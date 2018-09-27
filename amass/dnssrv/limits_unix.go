// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd

package dnssrv

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	defaultNumOpenFiles uint64 = 100000
)

func GetFileLimit() int {
	var limit int = int(defaultNumOpenFiles)
	var lim syscall.Rlimit

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		lim.Cur = lim.Max
		if lim.Cur == unix.RLIM_INFINITY || lim.Cur > defaultNumOpenFiles {
			lim.Cur = defaultNumOpenFiles
		}
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		limit = int(lim.Cur)
	}
	return limit
}
