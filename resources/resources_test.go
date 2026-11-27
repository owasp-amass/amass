// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"io"
	"testing"
)

// Every default file is embedded and has content.
func TestDefaultFilesAreEmbedded(t *testing.T) {
	for _, name := range DefaultFilesList {
		f, err := GetResourceFile(name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil || len(data) == 0 {
			t.Errorf("%s is empty or unreadable: %v", name, err)
		}
		if raw, err := GetResourceFileData(name); err != nil || len(raw) != len(data) {
			t.Errorf("%s: GetResourceFileData returned %d bytes, %v", name, len(raw), err)
		}
	}
}

func TestMissingResource(t *testing.T) {
	if _, err := GetResourceFile("no-such-file.txt"); err == nil {
		t.Error("a missing resource was opened")
	}
	if _, err := GetResourceFileData("no-such-file.txt"); err == nil {
		t.Error("a missing resource was read")
	}
}
