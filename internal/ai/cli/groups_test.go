// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	lenscli "github.com/owasp-amass/amass/v5/internal/lens/cli"
)

// amass ai still runs the operations that moved to amass lens and amass
// review, by their old names, with a note.
func TestMovedOperationsStillRun(t *testing.T) {
	var out, errout bytes.Buffer
	// amass ai takes the operation first or last.
	out.Reset()
	if err := Run(nil, &out, &errout, []string{"signals", "-format", "text"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Why it counts") {
		t.Errorf("operation first: %q", out.String()[:min(80, out.Len())])
	}

	// The old amass ai form still works, with a note.
	out.Reset()
	errout.Reset()
	if err := Run(nil, &out, &errout, []string{"-format", "text", "duplicate-signals"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errout.String(), "amass ai duplicate-signals is now amass review duplicate-signals") {
		t.Errorf("deprecation note: %q", errout.String())
	}
}

// No amass ai operation may shadow one that moved to amass lens or review.
func TestOperationsDoNotShadowMovedOnes(t *testing.T) {
	moved := lenscli.Operations()
	for _, op := range operations {
		if _, ok := moved[op]; ok {
			t.Errorf("amass ai %s is also %s", op, moved[op])
		}
	}
}
