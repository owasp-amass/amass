//go:build aix || darwin || dragonfly || freebsd || (js && wasm) || linux || nacl || netbsd || openbsd || solaris
// +build aix darwin dragonfly freebsd js,wasm linux nacl netbsd openbsd solaris

// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"syscall"
)

// GetFileLimit attempts to raise the ulimit to the maximum hard limit and returns that value.
func GetFileLimit() int {
	limit := 50000

	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		lim.Cur = lim.Max
		limit = int(lim.Cur)

		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
			return limit
		}
	}

	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err == nil {
		if cur := int(lim.Cur); cur < limit {
			limit = cur
		}
	}

	return limit
}
