// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build windows

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

	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit
	// Start final output operations
	close(e.Done)
	<-finished
	os.Exit(1)
}
