// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestRunRejectsBadArguments(t *testing.T) {
	var out, errout bytes.Buffer

	if err := Run("amass vuln-update", []string{"extra"}, &out, &errout); err == nil ||
		!strings.Contains(err.Error(), "unexpected arguments") {
		t.Errorf("an extra argument gave %v, want an unexpected arguments error", err)
	}
	if err := Run("amass vuln-update", []string{"-timeout", "0s"}, &out, &errout); err == nil {
		t.Error("a zero timeout was accepted")
	}
}

func TestRunHelp(t *testing.T) {
	var out, errout bytes.Buffer

	err := Run("amass vuln-update", []string{"-h"}, &out, &errout)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h gave %v, want flag.ErrHelp", err)
	}
	if !strings.Contains(errout.String(), "-vuln-data") || !strings.Contains(errout.String(), Description) {
		t.Errorf("the usage lacks the flags or description:\n%s", errout.String())
	}
}

// Refreshing more often than NVD's best practices allow is refused.
func TestRunEveryHasAMinimum(t *testing.T) {
	var out, errout bytes.Buffer

	err := Run("amass vuln-update", []string{"-every", "30m"}, &out, &errout)
	if err == nil || !strings.Contains(err.Error(), "at least 2h") {
		t.Errorf("-every 30m gave %v, want the 2h minimum", err)
	}
}
