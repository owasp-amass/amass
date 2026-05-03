//go:build !windows

// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"syscall"
)

func initCmd(p string) *exec.Cmd {
	cmd := exec.Command("nohup", p, "engine")

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	return cmd
}
