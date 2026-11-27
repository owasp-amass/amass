// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"testing"
)

func TestPersonNameKey(t *testing.T) {
	if personNameKey("Doe, Jane") != personNameKey("jane doe") {
		t.Error("word order and punctuation changed the name")
	}
	if personNameKey("Madonna") != "" {
		t.Error("a single word was taken for a person's name")
	}
}
