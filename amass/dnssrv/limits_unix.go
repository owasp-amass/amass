// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd

package dnssrv

import (
	"syscall"
)

const (
	defaultNumOpenFiles int64 = 10000
)

func GetFileLimit() int64 {
	var limit int64 = defaultNumOpenFiles
	var lim syscall.Rlimit

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		lim.Cur = lim.Max
		syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
	}

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		limit = int64(lim.Cur)
	}
	return limit
}
