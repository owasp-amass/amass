// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build windows

package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/core"
)

// If the user interrupts the program, print the summary information
func SignalHandler(e *amass.Enumeration, output chan *core.AmassOutput, done chan struct{}) {
	quit := make(chan os.Signal, 1)

	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit
	// Start final output operations
	close(output)
	// Wait for the broadcast indicating completion
	<-done
	os.Exit(1)
}
