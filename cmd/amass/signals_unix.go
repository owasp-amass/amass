// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/OWASP/Amass/amass/core"
)

// If the user interrupts the program, print the summary information
func signalHandler(e *core.Enumeration) {
	quit := make(chan os.Signal, 1)
	pause := make(chan os.Signal, 1)
	resume := make(chan os.Signal, 1)

	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	signal.Notify(pause, syscall.SIGTSTP)
	signal.Notify(resume, syscall.SIGCONT)
loop:
	for {
		select {
		case <-pause:
			e.Pause()
		case <-resume:
			e.Resume()
		case <-quit:
			// Start final output operations
			close(e.Done)
			<-finished
			break loop
		}
	}
	os.Exit(1)
}
