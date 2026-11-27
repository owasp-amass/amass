// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package afmt

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestFprintBannerRightAlignsTheDetails(t *testing.T) {
	saved := color.NoColor
	color.NoColor = true
	t.Cleanup(func() { color.NoColor = saved })

	var buf bytes.Buffer
	FprintBanner(&buf)

	out := buf.String()
	if !strings.Contains(out, Banner) {
		t.Fatal("the banner art is missing")
	}
	for _, detail := range []string{Version, Author, Description} {
		var line string
		for _, l := range strings.Split(out, "\n") {
			if strings.TrimSpace(l) == detail {
				line = l
			}
		}
		if line == "" {
			t.Errorf("%q is not on a line of its own", detail)
		} else if len(line) != 76 {
			t.Errorf("%q ends at column %d, want 76", detail, len(line))
		}
	}
}
