// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/OWASP/Amass/amass"
)

// If the user interrupts the program, print the summary information
func SignalHandler(e *amass.Enumeration, output chan *amass.AmassOutput, done chan struct{}) {
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
			close(output)
			// Wait for the broadcast indicating completion
			<-done
			break loop
		}
	}
	os.Exit(1)
}
