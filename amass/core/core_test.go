// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

import (
	"flag"
	"os"
	"testing"
)

var (
	networkTest  = flag.Bool("network", false, "Run tests that require connectivity (take more time)")
)

// TestMain will parse the test flags and setup for integration tests.
func TestMain(m *testing.M) {
	flag.Parse()

	result := m.Run()

	os.Exit(result)
}